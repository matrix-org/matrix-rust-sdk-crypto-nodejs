const { Attachment, EncryptedAttachment } = require("../");

describe(Attachment.name, () => {
    test("can encrypt data", () => {
        const originalData = Uint8Array.from({ length: 256 }, (_, i) => i);
        const encryptedAttachment = Attachment.encrypt(originalData);

        const serializedMediaEncryptionInfo = encryptedAttachment.mediaEncryptionInfo;
        const mediaEncryptionInfo = JSON.parse(serializedMediaEncryptionInfo);

        expect(mediaEncryptionInfo).toMatchObject({
            v: "v2",
            key: {
                kty: expect.any(String),
                key_ops: expect.arrayContaining(["encrypt", "decrypt"]),
                alg: expect.any(String),
                k: expect.any(String),
                ext: expect.any(Boolean),
            },
            iv: expect.stringMatching(/^[A-Za-z0-9\+/]+$/),
            hashes: {
                sha256: expect.stringMatching(/^[A-Za-z0-9\+/]+$/),
            },
        });

        const encryptedData = encryptedAttachment.encryptedData;
        expect(encryptedData).toBeInstanceOf(Uint8Array);
        expect(encryptedData).toHaveLength(originalData.length);
        expect(encryptedData).not.toStrictEqual(originalData);

        const reconstructedAttachment = new EncryptedAttachment(encryptedData, serializedMediaEncryptionInfo);
        expect(Attachment.decrypt(reconstructedAttachment)).toStrictEqual(originalData);
    });

    test("can decrypt data only once", () => {
        const originalData = Uint8Array.from({ length: 256 }, (_, i) => i);
        const encryptedAttachment = Attachment.encrypt(originalData);
        const encryptedData = new Uint8Array(encryptedAttachment.encryptedData);

        expect(encryptedAttachment.hasMediaEncryptionInfoBeenConsumed).toStrictEqual(false);

        const decryptedAttachment = Attachment.decrypt(encryptedAttachment);

        expect(decryptedAttachment).toStrictEqual(originalData);
        expect(encryptedAttachment.hasMediaEncryptionInfoBeenConsumed).toStrictEqual(true);
        expect(encryptedAttachment.mediaEncryptionInfo).toBeNull();
        expect(encryptedAttachment.encryptedData).toStrictEqual(encryptedData);

        expect(() => {
            Attachment.decrypt(encryptedAttachment);
        }).toThrow("The media encryption info are absent from the given encrypted attachment");
    });
});

describe(EncryptedAttachment.name, () => {
    const originalData = "hello";
    const textDecoder = new TextDecoder();

    test("can be created manually", () => {
        const encryptedAttachment = new EncryptedAttachment(
            new Uint8Array([24, 150, 67, 37, 144]),
            JSON.stringify({
                v: "v2",
                key: {
                    kty: "oct",
                    key_ops: ["encrypt", "decrypt"],
                    alg: "A256CTR",
                    k: "QbNXUjuukFyEJ8cQZjJuzN6mMokg0HJIjx0wVMLf5BM",
                    ext: true,
                },
                iv: "xk2AcWkomiYAAAAAAAAAAA",
                hashes: {
                    sha256: "JsRbDXgOja4xvDiF3DwBuLHdxUzIrVYIuj7W/t3aEok",
                },
            }),
        );

        expect(encryptedAttachment.hasMediaEncryptionInfoBeenConsumed).toStrictEqual(false);
        expect(textDecoder.decode(Attachment.decrypt(encryptedAttachment))).toStrictEqual(originalData);
        expect(encryptedAttachment.hasMediaEncryptionInfoBeenConsumed).toStrictEqual(true);
    });
});
