import { describe, expect, it } from 'vitest';
import { MemoryBlobStore, Vault } from 'sovereign-vault';
import {
  ACTION_RESTORED,
  ACTION_REVOKED,
  Attest,
  createSigningKey,
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
    expect(await attest.revocation(DIGEST)).toEqual({ revoked: false, receipt: null });
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
