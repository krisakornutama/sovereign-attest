import { describe, expect, it } from 'vitest';
import { MemoryBlobStore, Vault } from 'sovereign-vault';
import {
  ACTION_RESTORED,
  ACTION_REVOKED,
  Attest,
  createSigningKey,
  revocationCovers,
  sha256Hex,
  utf8,
} from '../src/index.js';

const MASTER_KEY = new Uint8Array(32).fill(6);
const BYTES = utf8('release 1.3.11');
const DIGEST = sha256Hex(BYTES);

async function openAttest() {
  const vault = await Vault.open({ store: new MemoryBlobStore(), masterKey: MASTER_KEY });
  let clock = 1_700_000_000_000;
  const attest = await Attest.open({ vault, keyId: 'release', now: () => (clock += 1000) });
  return attest;
}

function artifact() {
  return { name: 'app.exe', bytes: BYTES };
}

describe('revocation', () => {
  it('artifact ที่ยังไม่ถูกเพิกถอนรายงานว่าไม่ revoked', async () => {
    const attest = await openAttest();
    await attest.record({ action: 'artifact.shipped', actor: 'release-bot', artifact: artifact() });
    expect(await attest.revocation(DIGEST)).toEqual({
      revoked: false,
      receipt: null,
      revokedAt: null,
    });
  });

  it('revoke ต่อจาก shipped แล้วสถานะเปลี่ยน พร้อมเหตุผลที่เซ็นไว้', async () => {
    const attest = await openAttest();
    await attest.record({ action: 'artifact.shipped', actor: 'release-bot', artifact: artifact() });
    const revoked = await attest.revoke({
      artifact: artifact(),
      actor: 'security',
      reason: 'ล็อกอินของบิลด์นี้รั่ว',
    });

    expect(revoked.body.action).toBe(ACTION_REVOKED);
    expect(revoked.body.meta?.reason).toBe('ล็อกอินของบิลด์นี้รั่ว');
    const state = await attest.revocation(DIGEST);
    expect(state.revoked).toBe(true);
    expect(state.receipt?.id).toBe(revoked.id);
  });

  it('restore ยกเลิกการเพิกถอน และสถานะกลับมาเป็นปกติ', async () => {
    const attest = await openAttest();
    await attest.revoke({ artifact: artifact(), actor: 'security', reason: 'สงสัย' });
    const restored = await attest.restore({
      artifact: artifact(),
      actor: 'owner',
      reason: 'ตรวจแล้วไม่พบปัญหา',
    });
    expect(restored.body.action).toBe(ACTION_RESTORED);
    const state = await attest.revocation(DIGEST);
    expect(state.revoked).toBe(false);
    expect(state.receipt?.id).toBe(restored.id);
  });

  it('revoke ซ้ำหลัง restore กลับมา revoked อีกครั้ง (สถานะล่าสุดชนะ)', async () => {
    const attest = await openAttest();
    await attest.revoke({ artifact: artifact(), actor: 'security', reason: 'รอบแรก' });
    await attest.restore({ artifact: artifact(), actor: 'owner' });
    const second = await attest.revoke({
      artifact: artifact(),
      actor: 'security',
      reason: 'รอบสอง',
    });
    const state = await attest.revocation(DIGEST);
    expect(state.revoked).toBe(true);
    expect(state.receipt?.id).toBe(second.id);
  });

  it('revocation ต้องผ่านการตรวจลายเซ็นเหมือน receipt อื่น', async () => {
    const attest = await openAttest();
    await attest.revoke({ artifact: artifact(), actor: 'security', reason: 'x' });
    await expect(
      attest.revocation(DIGEST, { trustedKeys: { release: createSigningKey('release').publicKey } })
    ).rejects.toBeInstanceOf(Error);
  });
});

describe('revokedAt (วันที่มีผลของการเพิกถอน)', () => {
  it('ระบุ revokedAt ย้อนหลังได้ และสถานะรายงานค่านั้น', async () => {
    const attest = await openAttest();
    await attest.record({ action: 'artifact.shipped', actor: 'release-bot', artifact: artifact() });
    const revoked = await attest.revoke({
      artifact: artifact(),
      actor: 'security',
      reason: 'บิลด์นี้ถูกแก้ตั้งแต่ต้นเดือน',
      revokedAt: 1_600_000_000_000,
    });
    expect(revoked.body.meta?.revokedAt).toBe(1_600_000_000_000);
    const state = await attest.revocation(DIGEST);
    expect(state.revoked).toBe(true);
    expect(state.revokedAt).toBe(1_600_000_000_000);
  });

  it('ไม่ระบุ revokedAt ⇒ มีผล ณ เวลาที่เพิกถอน (ไม่ย้อนหลัง)', async () => {
    const attest = await openAttest();
    await attest.record({ action: 'artifact.shipped', actor: 'release-bot', artifact: artifact() });
    const revoked = await attest.revoke({ artifact: artifact(), actor: 'security', reason: 'x' });
    const state = await attest.revocation(DIGEST);
    expect(state.revokedAt).toBe(revoked.body.at);
  });

  it('revocationCovers ตัดสินตามวันที่มีผล: ก่อน/เท่ากับ = ถูกเพิกถอน, หลัง = บิลด์ใหม่', async () => {
    const attest = await openAttest();
    await attest.revoke({
      artifact: artifact(),
      actor: 'security',
      reason: 'x',
      revokedAt: 1_700_000_500_000,
    });
    const state = await attest.revocation(DIGEST);
    expect(revocationCovers(state, 1_700_000_400_000)).toBe(true);
    expect(revocationCovers(state, 1_700_000_500_000)).toBe(true);
    expect(revocationCovers(state, 1_700_000_500_001)).toBe(false);
  });

  it('restore ล้างวันที่มีผล ⇒ ไม่ครอบ receipt ใดอีก', async () => {
    const attest = await openAttest();
    await attest.revoke({
      artifact: artifact(),
      actor: 'security',
      reason: 'x',
      revokedAt: 1_700_000_500_000,
    });
    await attest.restore({ artifact: artifact(), actor: 'owner' });
    const state = await attest.revocation(DIGEST);
    expect(state.revokedAt).toBeNull();
    expect(revocationCovers(state, 1_700_000_000_000)).toBe(false);
  });

  it('revokedAt ที่ไม่ใช่เวลาจำนวนเต็มบวกถูกปฏิเสธ (ไม่เขียน receipt)', async () => {
    const attest = await openAttest();
    for (const bad of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      await expect(
        attest.revoke({ artifact: artifact(), actor: 'security', reason: 'x', revokedAt: bad })
      ).rejects.toBeInstanceOf(Error);
    }
    expect(await attest.revocation(DIGEST)).toEqual({
      revoked: false,
      receipt: null,
      revokedAt: null,
    });
  });
});
