import fs from 'fs';
import path from 'path';

function generateUniqueFileName(extension: string): string {
    const timestamp: number = Date.now();
    const randomString: string = Math.random().toString(36).substring(2, 8);
    return `${timestamp}-${randomString}.${extension}`;
}

export function saveBase64Image(base64String: string): Promise<string> {
    return new Promise<string>((resolve, reject) => {
        // Determine file extension
        const extensionMatch: RegExpMatchArray | null = base64String.match(/^data:image\/(\w+);base64,/);
        if (!extensionMatch || extensionMatch.length < 2) {
            return reject(new Error('Invalid base64 image format'));
        }
        const extension: string = extensionMatch[1];

        // Remove header of base64 string
        const base64Data: string = base64String.replace(/^data:image\/\w+;base64,/, '');
        const buffer: Buffer = Buffer.from(base64Data, 'base64');

        const fileName: string = generateUniqueFileName(extension);
        const filePath: string = path.join(__dirname, '../../public/temp/', fileName);

        fs.writeFile(filePath, buffer, (err: NodeJS.ErrnoException | null) => {
            if (err) {
                reject(new Error(`Error saving image: ${err.message}`));
            } else {
                resolve(fileName);
            }
        });
    });
}
