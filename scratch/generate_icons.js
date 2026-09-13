const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

function createPNG(width, height) {
    const signature = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);

    function createChunk(type, data) {
        const len = Buffer.alloc(4);
        len.writeUInt32BE(data.length, 0);

        const typeBuf = Buffer.from(type, 'ascii');
        const body = Buffer.concat([typeBuf, data]);

        const crc = Buffer.alloc(4);
        let c = ~0;
        for (let i = 0; i < body.length; i++) {
            c ^= body[i];
            for (let k = 0; k < 8; k++) {
                c = (c >>> 1) ^ ((c & 1) ? 0xEDB88320 : 0);
            }
        }
        crc.writeInt32BE(~c, 0);

        return Buffer.concat([len, body, crc]);
    }

    const ihdrData = Buffer.alloc(13);
    ihdrData.writeUInt32BE(width, 0);
    ihdrData.writeUInt32BE(height, 4);
    ihdrData.writeUInt8(8, 8);
    ihdrData.writeUInt8(6, 9);
    ihdrData.writeUInt8(0, 10);
    ihdrData.writeUInt8(0, 11);
    ihdrData.writeUInt8(0, 12);
    const ihdr = createChunk('IHDR', ihdrData);

    const scanlineLength = width * 4 + 1;
    const rawData = Buffer.alloc(scanlineLength * height);

    for (let y = 0; y < height; y++) {
        const offset = y * scanlineLength;
        rawData.writeUInt8(0, offset);
        for (let x = 0; x < width; x++) {
            const pxOffset = offset + 1 + (x * 4);
            const isCenter = Math.abs(x - width / 2) < width * 0.35 && Math.abs(y - height / 2) < height * 0.35;
            if (isCenter) {
                rawData.writeUInt8(56, pxOffset);     // Cyan R
                rawData.writeUInt8(189, pxOffset + 1); // Cyan G
                rawData.writeUInt8(248, pxOffset + 2); // Cyan B
                rawData.writeUInt8(255, pxOffset + 3); // A
            } else {
                rawData.writeUInt8(2, pxOffset);       // Blue R
                rawData.writeUInt8(132, pxOffset + 1); // Blue G
                rawData.writeUInt8(199, pxOffset + 2); // Blue B
                rawData.writeUInt8(255, pxOffset + 3); // A
            }
        }
    }

    const compressed = zlib.deflateSync(rawData);
    const idat = createChunk('IDAT', compressed);
    const iend = createChunk('IEND', Buffer.alloc(0));

    return Buffer.concat([signature, ihdr, idat, iend]);
}

const targetDir = path.resolve('c:/Users/Asus/.antigravity-ide/sih-project/extension/icons');
fs.mkdirSync(targetDir, { recursive: true });

fs.writeFileSync(path.join(targetDir, 'icon-16.png'), createPNG(16, 16));
fs.writeFileSync(path.join(targetDir, 'icon-48.png'), createPNG(48, 48));
fs.writeFileSync(path.join(targetDir, 'icon-128.png'), createPNG(128, 128));

console.log("✅ Successfully created icons in:", targetDir);
