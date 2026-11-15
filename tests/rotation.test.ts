import { describe, expect, it } from 'vitest';
import { MemoryBlobStore, Vault } from 'sovereign-vault';
import {
  Attest,
  AttestError,
  createSigningKey,
  expandTrust,
  openRotation,
  sealRotation,
  sha256Hex,
  utf8,
} from '../src/index.js';

const MASTER_KEY = new Uint8Array(32).fill(4);
const BYTES = utf8('artifact under rotation');

function statementFor() {
  const oldKey = createSigningKey('release');
  const newKey = createSigningKey('release-2');
  return { oldKey, newKey, statement: sealRotation(oldKey, newKey, 1_700_000_000_000) };
}

describe('sealRotation / openRotation', () => {
  it('ยอมรับใบที่กุญแจเก่าเซ็นและผู้ตรวจ pin กุญแจเก่าไว้', () => {
    const { oldKey, newKey, statement } = statementFor();
    const opened = openRotation(statement, oldKey.publicKey);
    expect(opened.from).toEqual({ keyId: oldKey.keyId, publicKey: oldKey.publicKey });
    expect(opened.to).toEqual({ keyId: newKey.keyId, publicKey: newKey.publicKey });
    expect(opened.at).toBe(1_700_000_000_000);
  });

  it('ปฏิเสธใบที่ไม่ได้ endorse โดยกุญแจที่เราเชื่อ', () => {
    const { statement } = statementFor();
    expect(() => openRotation(statement, createSigningKey('release').publicKey)).toThrow(
      AttestError
    );
  });

  it('ปฏิเสธใบที่ถูกแก้ (ปลายทาง/เวลา) แม้รูปยังถูก', () => {
    const { oldKey, statement } = statementFor();
    const otherKey = createSigningKey('release-3');
    const editedTo = { ...statement, to: { keyId: 'release-3', publicKey: otherKey.publicKey } };
    expect(() => openRotation(editedTo, oldKey.publicKey)).toThrow(/signature/);
    const editedAt = { ...statement, at: statement.at + 1 };
    expect(() => openRotation(editedAt, oldKey.publicKey)).toThrow(/signature/);
  });

  it('ปฏิเสธรูปที่ไม่ใช่ใบ rotation และการ rotate ไปตัวเอง', () => {
    const { oldKey } = statementFor();
    for (const junk of [null, 42, {}, { v: 2, sig: 'x', at: 1 }]) {
      expect(() => openRotation(junk, oldKey.publicKey)).toThrow(AttestError);
    }
    expect(() => sealRotation(oldKey, createSigningKey('release'), 1)).toThrow(/itself/);
  });
});

describe('expandTrust', () => {
  it('เพิ่มกุญแจปลายทางให้เมื่อใบถูก endorse โดยกุญแจที่เชื่ออยู่', () => {
    const { oldKey, newKey, statement } = statementFor();
    const trust = expandTrust({ release: oldKey.publicKey }, [statement]);
    expect(trust).toMatchObject({ release: oldKey.publicKey, 'release-2': newKey.publicKey });
  });

  it('เดินหลายทอดได้แม้ใบมาไม่เรียงลำดับ (k1→k2→k3)', () => {
    const k1 = createSigningKey('k1');
    const k2 = createSigningKey('k2');
    const k3 = createSigningKey('k3');
    const first = sealRotation(k1, k2, 1);
    const second = sealRotation(k2, k3, 2);
    const trust = expandTrust({ k1: k1.publicKey }, [second, first]);
    expect(Object.keys(trust).sort()).toEqual(['k1', 'k2', 'k3']);
  });

  it('ปฏิเสธใบที่ไม่มีใคร endorse และไม่ปล่อยให้กุญแจปลอม bootstrap ตัวเอง', () => {
    const rogue = createSigningKey('rogue');
    const victim = createSigningKey('release');
    const stolen = sealRotation(rogue, victim, 1);
    expect(() => expandTrust({ release: victim.publicKey }, [stolen])).toThrow(/not endorsed/);
    const forgedSelf = sealRotation(rogue, createSigningKey('rogue-2'), 1);
    expect(() => expandTrust({ release: victim.publicKey }, [forgedSelf])).toThrow(/not endorsed/);
  });

  it('ปฏิเสธรูปที่ผิดก่อนพยายามตรวจ', () => {
    expect(() => expandTrust({ a: 'x' }, [{ nonsense: true }])).toThrow(/unknown shape/);
  });
});

describe('Attest.rotate', () => {
  async function openAttest() {
    const vault = await Vault.open({ store: new MemoryBlobStore(), masterKey: MASTER_KEY });
    let clock = 1_700_000_000_000;
    const attest = await Attest.open({ vault, keyId: 'release', now: () => (clock += 1000) });
    return { vault, attest };
  }

  it('สลับกุญแจที่ใช้เซ็น และเก็บใบ rotation ไว้ใน vault', async () => {
    const { attest } = await openAttest();
    const oldPublic = attest.publicKey;
    const statement = await attest.rotate('release-2');

    expect(attest.keyId).toBe('release-2');
    expect(attest.publicKey).not.toBe(oldPublic);
    expect(statement.from.publicKey).toBe(oldPublic);
    expect(await attest.rotationTo('release-2', oldPublic)).toEqual(statement);

    const receipt = await attest.record({
      action: 'artifact.built',
      actor: 'ci',
      artifact: { name: 'app.exe', bytes: BYTES },
    });
    expect(receipt.keyId).toBe('release-2');
  });

  it('provenance ข้ามรอยต่อกุญแจต้องมีใบ rotation ไม่งั้นถูกปฏิเสธ', async () => {
    const { attest } = await openAttest();
    const before = await attest.record({
      action: 'artifact.built',
      actor: 'ci',
      artifact: { name: 'app.exe', bytes: BYTES },
    });
    const oldPublic = attest.publicKey;
    const statement = await attest.rotate('release-2');
    const after = await attest.record({
      action: 'artifact.shipped',
      actor: 'release-bot',
      artifact: { name: 'app.exe', bytes: BYTES },
    });
    const digest = sha256Hex(BYTES);
    expect(after.body.prev).toBe(before.id);

    const trustedOld = { release: oldPublic };
    await expect(attest.provenance(digest, { trustedKeys: trustedOld })).rejects.toMatchObject({
      code: 'unknown-key',
    });

    const report = await attest.provenance(digest, {
      trustedKeys: trustedOld,
      rotations: [statement],
    });
    expect(report.receipts.map((receipt) => receipt.keyId)).toEqual(['release', 'release-2']);
  });

  it('ไม่ยอม rotate ไปกุญแจที่ใช้อยู่ และแจ้งเมื่อไม่มีใบของ keyId นั้น', async () => {
    const { attest } = await openAttest();
    await expect(attest.rotate('release')).rejects.toThrow(/already signing/);
    await expect(attest.rotationTo('nope')).rejects.toMatchObject({ code: 'unknown-key' });
  });

  it('บล็อกใบที่ถูกแก้ใน vault ก่อนใช้', async () => {
    const { vault, attest } = await openAttest();
    const statement = await attest.rotate('release-2');
    await vault.put(
      'attest/rotations/release-2.json',
      utf8(JSON.stringify({ ...statement, at: statement.at + 1 }))
    );
    await expect(attest.rotationTo('release-2')).rejects.toBeInstanceOf(AttestError);
  });
});
