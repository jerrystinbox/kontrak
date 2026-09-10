const { Client } = require('@notionhq/client');
const crypto = require('crypto');
const formidable = require('formidable');
const fs = require('fs');

const notion = new Client({ auth: process.env.NOTION_TOKEN });

// --- KONFIGURASI KUNCI ENKRIPSI ---
// Menggunakan process.env.ENCRYPTION_KEY jika ada, atau fallback turunan dari NOTION_TOKEN / Default Key
const SECRET_KEY_RAW = process.env.ENCRYPTION_KEY || process.env.NOTION_TOKEN || 'arsip_secret_key_default_32bytes_!';
const SECRET_KEY = crypto.createHash('sha256').update(SECRET_KEY_RAW).digest(); // Pastikan tepat 32 bytes

// Konfigurasi Mapping Database dan PIN
const CONFIG = {   
    gg55:    { BusinessID: "GG",    pageTitle: "Kontrak Kantor Hijau 🔒︎",         db: process.env.NOTION_DB_KONTRAK_KANTOR,    pinAdmin: process.env.PIN_ADMIN, pinInsert: process.env.PIN_ADMIN },
    gg22:    { BusinessID: "GG",    pageTitle: "Kontrak Kantor Hijau 🔍︎",         db: process.env.NOTION_DB_KONTRAK_KANTOR,    pinAdmin: "2095231",             pinInsert: "2095231" },
    gg42:    { BusinessID: "GG",    pageTitle: "Kontrak Kantor Hijau",            db: process.env.NOTION_DB_KONTRAK_KANTOR,    pinAdmin: "251011",              pinInsert: "251011" }
};

export const config = {
    api: { bodyParser: false },
};

// Helper Enkripsi Payload Object ke Token Hex (AES-256-GCM)
function encryptToken(payloadObj) {
    try {
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', SECRET_KEY, iv);
        let encrypted = cipher.update(JSON.stringify(payloadObj), 'utf8', 'hex');
        encrypted += cipher.final('hex');
        const authTag = cipher.getAuthTag().toString('hex');
        return `${iv.toString('hex')}.${authTag}.${encrypted}`;
    } catch (e) {
        console.error('Encryption error:', e);
        return null;
    }
}

// Helper Dekripsi Token Hex ke Payload Object
function decryptToken(tokenString) {
    if (!tokenString || typeof tokenString !== 'string') return null;
    try {
        const parts = tokenString.split('.');
        if (parts.length !== 3) return null;
        const [ivHex, authTagHex, encryptedHex] = parts;

        const decipher = crypto.createDecipheriv('aes-256-gcm', SECRET_KEY, Buffer.from(ivHex, 'hex'));
        decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));
        let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return JSON.parse(decrypted);
    } catch (e) {
        return null; // Token rusak atau diubah
    }
}

// Helper ekstraksi nilai Rollup/Properti secara aman dari respons Notion API
function getRollupValue(rollupProp) {
    if (!rollupProp) return '';
    
    // Jika ternyata properti biasa (bukan rollup): title, rich_text, select
    if (rollupProp.type === 'title') return rollupProp.title?.map(t => t.plain_text).join('') || '';
    if (rollupProp.type === 'rich_text') return rollupProp.rich_text?.map(t => t.plain_text).join('') || '';
    if (rollupProp.type === 'select') return rollupProp.select?.name || '';

    if (rollupProp.type !== 'rollup') return '';
    const rollupData = rollupProp.rollup;
    if (!rollupData) return '';

    // Jika rollup bertipe string / number langsung
    if (rollupData.type === 'string') return rollupData.string || '';
    if (rollupData.type === 'number') return rollupData.number !== null ? String(rollupData.number) : '';

    // Jika rollup bertipe array
    if (rollupData.type === 'array' && Array.isArray(rollupData.array) && rollupData.array.length > 0) {
        return rollupData.array.map(item => {
            if (item.type === 'title') return item.title?.map(t => t.plain_text).join('') || '';
            if (item.type === 'rich_text') return item.rich_text?.map(t => t.plain_text).join('') || '';
            if (item.type === 'select') return item.select?.name || '';
            if (item.type === 'formula') {
                return item.formula?.string || (item.formula?.number !== undefined ? String(item.formula.number) : '');
            }
            if (item.type === 'number') return item.number !== null ? String(item.number) : '';
            return '';
        }).filter(Boolean).join(', ');
    }
    return '';
}

// Helper Ekstraksi Property Notion Ke Format JSON Output (Lama + Baru)
function mapPageProperties(page, type) {
    const props = page.properties;
    const docs = props.DOKUMENTASI?.files.map(f => ({
        name: f.name,
        url: f.type === 'file' ? f.file.url : (f.external?.url || f.file_upload?.url || "")
    })) || [];

    const recordToken = encryptToken({ type: type, id: page.id });

    return {
        id: page.id,
        token: recordToken,
        rec_id: props.REC_ID?.unique_id?.number || props["№ Emp_ID"]?.unique_id?.number || "-",
        judul: props.JUDUL?.title?.map(t => t.plain_text).join("") || "",
        status: props.STATUS?.select?.name || "",
        mulai: props.MULAI?.date?.start ? props.MULAI.date.start.split('T')[0] : "",
        selesai: props.SELESAI?.date?.start ? props.SELESAI.date.start.split('T')[0] : "",
        harga_sewa: props.HARGA_SEWA?.rich_text?.map(t => t.plain_text).join("") || "",
        jaminan: props.JAMINAN?.rich_text?.map(t => t.plain_text).join("") || "",
        keterangan: props.KETERANGAN?.rich_text?.map(t => t.plain_text).join("") || "",
        memo: props.MEMO?.rich_text?.map(t => t.plain_text).join("") || "",
        penyewa_id: props.PENYEWA?.relation?.[0]?.id || "",
        property_id: props.PROPERTY?.relation?.[0]?.id || "",
        // --- PROPERTI ROLLUP / RELASI ---
        nama_penyewa: getRollupValue(props.NAMA_PENYEWA),
        nama_property: getRollupValue(props.NAMA_PROPERTY),
        alamat_property: getRollupValue(props.ALAMAT_PROPERTY) || getRollupValue(props.LOKASI_PROPERTY) || getRollupValue(props.ALAMAT),
        pic_penyewa: getRollupValue(props.PIC_PENYEWA),
        hp_pic_penyewa: getRollupValue(props.HP_PIC_PENYEWA),
        // ----------------------------
        dokumentasi: docs,
        submitted: props["Created time"]?.created_time || props["Created Time"]?.created_time || page.created_time || ""
    };
}

// Helper untuk membangun propertiesData secara aman & presisi sesuai skema Notion DB / Page
async function buildPropertiesData(notion, targetId, databaseId, fields) {
    let propSchema = {};
    if (targetId && targetId.trim() !== '' && targetId !== 'undefined') {
        try {
            const page = await notion.pages.retrieve({ page_id: targetId });
            propSchema = page.properties || {};
        } catch (e) {
            console.error('Failed to retrieve page schema:', e);
        }
    } else {
        try {
            const db = await notion.databases.retrieve({ database_id: databaseId });
            propSchema = db.properties || {};
        } catch (e) {
            console.error('Failed to retrieve DB schema:', e);
        }
    }

    const { 
        rec_id, judul, status, mulai, selesai, harga_sewa, jaminan, keterangan, memo, penyewa_id, property_id, formattedFiles 
    } = fields;

    const propertiesData = {};

    // 1. REC_ID / № REC_ID / № Emp_ID
    const recIdKey = propSchema['REC_ID'] ? 'REC_ID' : (propSchema['№ REC_ID'] ? '№ REC_ID' : (propSchema['№ Emp_ID'] ? '№ Emp_ID' : null));
    if (recIdKey && rec_id !== undefined) {
        const type = propSchema[recIdKey].type;
        if (type === 'rich_text') {
            propertiesData[recIdKey] = { rich_text: [{ text: { content: String(rec_id || "") } }] };
        } else if (type === 'number') {
            const numVal = parseInt(rec_id, 10);
            propertiesData[recIdKey] = { number: !isNaN(numVal) ? numVal : null };
        }
        // Jika type === 'unique_id', di-skip otomatis karena auto-generated oleh Notion API
    }

    // 2. JUDUL (title)
    if (propSchema['JUDUL'] && judul !== undefined) {
        propertiesData['JUDUL'] = { title: [{ text: { content: judul || "" } }] };
    }

    // 3. STATUS (select / rich_text)
    if (propSchema['STATUS'] && status !== undefined) {
        const type = propSchema['STATUS'].type;
        if (type === 'select') {
            propertiesData['STATUS'] = status ? { select: { name: status } } : { select: null };
        } else if (type === 'rich_text') {
            propertiesData['STATUS'] = { rich_text: [{ text: { content: status || "" } }] };
        }
    }

    // 4. MULAI (date)
    if (propSchema['MULAI'] && mulai !== undefined) {
        propertiesData['MULAI'] = { date: mulai ? { start: mulai } : null };
    }

    // 5. SELESAI (date)
    if (propSchema['SELESAI'] && selesai !== undefined) {
        propertiesData['SELESAI'] = { date: selesai ? { start: selesai } : null };
    }

    // 6. HARGA_SEWA (rich_text / number)
    if (propSchema['HARGA_SEWA'] && harga_sewa !== undefined) {
        propertiesData['HARGA_SEWA'] = { rich_text: [{ text: { content: String(harga_sewa || "") } }] };
    }

    // 7. JAMINAN (rich_text / number)
    if (propSchema['JAMINAN'] && jaminan !== undefined) {
        propertiesData['JAMINAN'] = { rich_text: [{ text: { content: String(jaminan || "") } }] };
    }

    // 8. KETERANGAN (rich_text)
    if (propSchema['KETERANGAN'] && keterangan !== undefined) {
        propertiesData['KETERANGAN'] = { rich_text: [{ text: { content: keterangan || "" } }] };
    }

    // 9. MEMO (rich_text)
    if (propSchema['MEMO'] && memo !== undefined) {
        propertiesData['MEMO'] = { rich_text: [{ text: { content: memo || "" } }] };
    }

    // 9a. PENYEWA (relation)
    if (propSchema['PENYEWA'] && penyewa_id !== undefined) {
        propertiesData['PENYEWA'] = {
            relation: penyewa_id ? [{ id: penyewa_id }] : []
        };
    }

    // 9b. PROPERTY (relation)
    if (propSchema['PROPERTY'] && property_id !== undefined) {
        propertiesData['PROPERTY'] = {
            relation: property_id ? [{ id: property_id }] : []
        };
    }

    // 10. DOKUMENTASI (files)
    if (propSchema['DOKUMENTASI'] && formattedFiles !== undefined) {
        propertiesData['DOKUMENTASI'] = { files: formattedFiles || [] };
    }

    return propertiesData;
}

function parseMultipart(req) {
    const form = new formidable.IncomingForm({ keepExtensions: true });
    return new Promise((resolve, reject) => {
        form.parse(req, (err, fields, files) => {
            if (err) reject(err);
            else resolve({ fields, files });
        });
    });
}

function parseJson(req) {
    return new Promise((resolve) => {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', () => {
            try { resolve(JSON.parse(body)); }
            catch (e) { resolve({}); }
        });
    });
}

const getSingleValue = (val) => Array.isArray(val) ? val[0] : val;

async function runLazyCleanup() {
    if (!process.env.BLOB_READ_WRITE_TOKEN) return;
    try {
        const { list, del } = await import('@vercel/blob');
        const { blobs } = await list({ prefix: 'temp/' });
        const now = Date.now();
        const ONE_HOUR = 3600000;
        const expiredBlobs = blobs.filter(b => (now - new Date(b.uploadedAt).getTime()) > ONE_HOUR);
        
        if (expiredBlobs.length > 0) {
            await del(expiredBlobs.map(b => b.url));
            console.log(`[Lazy Cleanup] Berhasil menghapus ${expiredBlobs.length} file usang di temp/`);
        }
    } catch (err) {
        console.error('[Lazy Cleanup Error]:', err.message);
    }
}

export default async function handler(req, res) {
    let bodyFields = {};
    let uploadedFiles = {};

    // Parse Body Jika Method PUT/POST/DELETE
    if (req.method === 'PUT' || req.method === 'POST' || req.method === 'DELETE') {
        const contentType = req.headers['content-type'] || '';
        if (contentType.includes('multipart/form-data')) {
            const data = await parseMultipart(req);
            bodyFields = data.fields;
            uploadedFiles = data.files;
        } else {
            bodyFields = await parseJson(req);
        }
    }

    // --- EKSTRAKSI DAN DEKRIPSI PARAMETER ---
    const rawToken = req.query.token || getSingleValue(bodyFields.token);
    let decodedType = null;
    let decodedId = null;
    
    if (rawToken) {
        const decrypted = decryptToken(rawToken);
        if (decrypted) {
            decodedType = decrypted.type || decrypted.dbid;
            decodedId = decrypted.id;
        }
    }

    // Fallback jika tidak ada token, gunakan query/body langsung
    const type = decodedType || req.query.type || req.query.dbid || getSingleValue(bodyFields.type) || getSingleValue(bodyFields.dbid);
    const targetId = decodedId || req.query.id || getSingleValue(bodyFields.id);

    const selectedConfig = CONFIG[type];

    if (!selectedConfig) {
        return res.status(400).json({ error: 'Token atau parameter database tidak valid / tidak ditemukan.' });
    }

    const databaseId = selectedConfig.db;
    const PIN_ADMIN = selectedConfig.pinAdmin;
    const PIN_INSERT = selectedConfig.pinInsert || PIN_ADMIN;

    // 1. Auth Endpoint Direct Upload Blob
    if (req.query.action === 'blob-auth') {
        try {
            const blobToken = process.env.BLOB_READ_WRITE_TOKEN;
            if (!blobToken) return res.status(400).json({ error: 'BLOB_READ_WRITE_TOKEN belum dipasang.' });

            const body = bodyFields || {};
            const { handleUpload } = await import('@vercel/blob/client');
            const jsonResponse = await handleUpload({
                body: body,
                request: req,
                token: blobToken,
                onBeforeGenerateToken: async () => ({
                    allowedContentTypes: [
                        // Gambar
                        'image/png', 'image/jpeg', 'image/webp', 'image/gif', 'image/svg+xml', 'image/heic', 'image/heif', 'image/bmp', 'image/tiff',
                        // Dokumen & Teks
                        'application/pdf', 'application/msword', 
                        'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 
                        'application/vnd.ms-excel', 
                        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                        'application/vnd.ms-powerpoint',
                        'application/vnd.openxmlformats-officedocument.presentationml.presentation',
                        'text/plain', 'text/csv',
                        // Arsip / Kompresi
                        'application/zip', 'application/x-zip-compressed', 'application/x-rar-compressed', 'application/x-7z-compressed',
                        // Audio & Video
                        'audio/mpeg', 'audio/wav', 'audio/ogg', 'audio/mp4', 'audio/x-m4a',
                        'video/mp4', 'video/webm', 'video/quicktime', 'video/x-msvideo',
                        // File Koding & Teks Pemrograman
                        'text/html', 'text/css', 'text/javascript', 'application/javascript', 
                        'application/json', 'text/xml', 'application/xml',
                        'text/x-python', 'text/x-php', 'text/x-c', 'text/x-c++', 'text/x-java-source', 'text/x-sql', 'text/markdown'
                    ],
                    tokenPayload: JSON.stringify({})
                }),
                onUploadCompleted: async () => {}
            });
            return res.status(200).json(jsonResponse);
        } catch (error) {
            return res.status(400).json({ error: error.message });
        }
    }
    
    // 2. GET DATA TUNGGAL ATAU LIST
    if (req.method === 'GET') {
        
        // A. JIKA TIDAK ADA targetId -> Kembalikan List Data (untuk index.html)
        if (!targetId) {
            try {
                const response = await notion.databases.query({
                    database_id: databaseId,
                    sorts: [
                        {
                            property: 'SELESAI',
                            direction: 'ascending'
                        }
                    ],
                    page_size: 100
                });

                const inputToken = encryptToken({ type: type });
                const data = response.results.map(page => mapPageProperties(page, type));

                // --- LOGIKA URUTAN: Tanggal Selesai ASCENDING -> Tanggal Mulai Terlama ---
                data.sort((a, b) => {
                    const timeSelesaiA = (a.selesai && a.selesai.trim()) ? new Date(a.selesai.trim()).getTime() : null;
                    const timeSelesaiB = (b.selesai && b.selesai.trim()) ? new Date(b.selesai.trim()).getTime() : null;

                    // 1. Jika keduanya punya tanggal selesai -> Urutkan dari yang paling awal/tua selesainya (ASCENDING)
                    if (timeSelesaiA && timeSelesaiB) {
                        if (timeSelesaiA !== timeSelesaiB) return timeSelesaiA - timeSelesaiB;
                    }

                    // 2. Jika hanya satu yang ada tanggal selesai -> Utamakan yang punya tanggal selesai
                    if (timeSelesaiA && !timeSelesaiB) return -1;
                    if (!timeSelesaiA && timeSelesaiB) return 1;

                    // 3. Jika tanggal selesai kosong -> Urutkan berdasarkan Tanggal Mulai (Paling Lama ke Terbaru)
                    const timeMulaiA = (a.mulai && a.mulai.trim()) ? new Date(a.mulai.trim()).getTime() : null;
                    const timeMulaiB = (b.mulai && b.mulai.trim()) ? new Date(b.mulai.trim()).getTime() : null;

                    if (timeMulaiA && timeMulaiB) {
                        if (timeMulaiA !== timeMulaiB) return timeMulaiA - timeMulaiB;
                    } else if (timeMulaiA && !timeMulaiB) {
                        return -1;
                    } else if (!timeMulaiA && timeMulaiB) {
                        return 1;
                    }

                    return (a.judul || "").localeCompare(b.judul || "", 'id', { sensitivity: 'base' });
                });

                return res.status(200).json({ 
                    success: true, 
                    pageTitle: selectedConfig.pageTitle, 
                    dbid: type,
                    inputToken: inputToken,
                    data: data
                });
            } catch (error) {
                console.error('Error fetching list from Notion:', error);
                return res.status(500).json({ success: false, error: 'Gagal mengambil data: ' + error.message });
            }
        } 
        // B. JIKA ADA targetId -> Kembalikan Data Tunggal (untuk view.html & edit.html)
        else {
            try {
                const page = await notion.pages.retrieve({ page_id: targetId });
                const singleData = mapPageProperties(page, type);

                return res.status(200).json({ 
                    success: true, 
                    pageTitle: selectedConfig.pageTitle, 
                    dbid: type,
                    data: singleData 
                });
            } catch (error) {
                console.error('Error fetching single page from Notion:', error);
                return res.status(500).json({ success: false, error: 'Gagal mengambil data tunggal: ' + error.message });
            }
        }
    }
    
    // 2.5 FETCH / QUERY LIST DATA KONTRAK
    if (req.method === 'POST' && req.query.action !== 'create' && req.query.action !== 'blob-auth') {
        try {
            // Tambahkan aksi metadata (mengembalikan status 200 OK tanpa perlu PIN)
            if (req.query.action === 'metadata') {
                return res.status(200).json({
                    success: true,
                    pageTitle: selectedConfig.pageTitle,
                    dbid: type
                });
            }

            const { keyword, startDate, endDate, cursor, pin, sortBy } = bodyFields;

            // Validasi PIN Admin untuk Membuka & Memuat List Data Kontrak
            if (pin !== PIN_ADMIN) {
                return res.status(403).json({ 
                    error: 'PIN Salah! Akses ditolak.',
                    pageTitle: selectedConfig.pageTitle,
                    dbid: type
                });
            }

            const filterConditions = [];

            if (startDate) {
                filterConditions.push({ property: 'MULAI', date: { on_or_after: startDate } });
            }
            if (endDate) {
                filterConditions.push({ property: 'MULAI', date: { on_or_before: endDate } });
            }
            if (keyword && keyword.trim() !== '') {
                const words = keyword.trim().split(/\s+/);
                words.forEach(word => {
                    filterConditions.push({
                        or: [
                            { property: 'JUDUL', title: { contains: word } },
                            { property: 'KETERANGAN', rich_text: { contains: word } }
                        ]
                    });
                });
            }

            let filter = undefined;
            if (filterConditions.length === 1) {
                filter = filterConditions[0];
            } else if (filterConditions.length > 1) {
                filter = { and: filterConditions };
            }

            // GANTI: Sesuaikan pengurutan query ke Notion Database
            let notionSorts = [{ property: 'MULAI', direction: 'ascending' }];
            if (sortBy === 'judul') notionSorts = [{ property: 'JUDUL', direction: 'ascending' }];
            else if (sortBy === 'keterangan') notionSorts = [{ property: 'KETERANGAN', direction: 'ascending' }];

            const response = await notion.databases.query({
                database_id: databaseId,
                filter: filter,
                sorts: notionSorts,
                start_cursor: cursor || undefined,
                page_size: 20
            });

            const inputToken = encryptToken({ type: type });
            const data = response.results.map(page => mapPageProperties(page, type));

            data.sort((a, b) => {
                const nameA = (a.judul || "").trim();
                const nameB = (b.judul || "").trim();

                if (sortBy === 'judul') return nameA.localeCompare(nameB, 'id', { sensitivity: 'base' });
                if (sortBy === 'status') return (a.status || "").trim().localeCompare((b.status || "").trim(), 'id', { sensitivity: 'base' });
                if (sortBy === 'keterangan') return (a.keterangan || "").trim().localeCompare((b.keterangan || "").trim(), 'id', { sensitivity: 'base' });

                const timeA = (a.mulai && a.mulai.trim()) ? new Date(a.mulai.trim()).getTime() : null;
                const timeB = (b.mulai && b.mulai.trim()) ? new Date(b.mulai.trim()).getTime() : null;

                if (!timeA && !timeB) return nameA.localeCompare(nameB, 'id', { sensitivity: 'base' });
                if (!timeA) return 1;
                if (!timeB) return -1;

                if (timeA !== timeB) return timeA - timeB;
                return nameA.localeCompare(nameB, 'id', { sensitivity: 'base' });
            });

            return res.status(200).json({
                pageTitle: selectedConfig.pageTitle,
                dbid: type,
                inputToken: inputToken,
                data: data,
                has_more: response.has_more,
                next_cursor: response.next_cursor
            });
        } catch (error) {
            return res.status(500).json({ error: 'Gagal mengambil data: ' + error.message });
        }
    }

    // 3. TAMBAH BARU / UPDATE DATA
    if (req.method === 'PUT' || (req.method === 'POST' && req.query.action === 'create')) {
        const rec_id = getSingleValue(bodyFields.rec_id);
        const judul = getSingleValue(bodyFields.judul);
        const status = getSingleValue(bodyFields.status);
        const mulai = getSingleValue(bodyFields.mulai);
        const selesai = getSingleValue(bodyFields.selesai);
        const harga_sewa = getSingleValue(bodyFields.harga_sewa);
        const jaminan = getSingleValue(bodyFields.jaminan);
        const keterangan = getSingleValue(bodyFields.keterangan);
        const memo = getSingleValue(bodyFields.memo);
        const penyewa_id = getSingleValue(bodyFields.penyewa_id);
        const property_id = getSingleValue(bodyFields.property_id);
        const pin = getSingleValue(bodyFields.pin);
        const existingFilesStr = getSingleValue(bodyFields.existingFiles);
        const newFilesBlobsStr = getSingleValue(bodyFields.newFilesBlobs);

        const isCreateMode = (!targetId || targetId.trim() === '' || targetId === 'undefined');

        // Validasi PIN
        if (isCreateMode) {
            if (pin !== PIN_INSERT && pin !== PIN_ADMIN) {
                return res.status(403).json({ message: 'PIN Input Salah!' });
            }
        } else {
            if (pin !== PIN_ADMIN) {
                return res.status(403).json({ message: 'PIN Edit Salah! (Hanya PIN Admin yang dapat mengubah data)' });
            }
        }

        try {
            const existingFiles = existingFilesStr ? JSON.parse(existingFilesStr) : [];
            const formattedFiles = existingFiles.map(f => {
                const isNotionHosted = f.url.includes('notion-static.com') || f.url.includes('s3.amazonaws.com') || f.url.includes('prod-files-secure');
                return {
                    name: f.name,
                    type: isNotionHosted ? "file" : "external",
                    [isNotionHosted ? "file" : "external"]: { url: f.url }
                };
            });

            const newFilesBlobs = newFilesBlobsStr ? JSON.parse(newFilesBlobsStr) : [];

            // --- GABUNGKAN BLOB FILE & DIRECT FILE KE DALAM SATU ANTREAN ---
            const filesToUploadToNotion = [];

            // 1. Ekstrak data file dari URL Vercel Blob (Hanya berjalan jika user mengupload file > 4MB)
            if (newFilesBlobs.length > 0) {
                const { del } = await import('@vercel/blob'); // Impor dilakukan secara kondisional di sini
                
                for (const item of newFilesBlobs) {
                    if (!item.blobUrl) continue;
                    const blobRes = await fetch(item.blobUrl);
                    if (!blobRes.ok) throw new Error(`Gagal membaca berkas sementara "${item.filename}"`);
                    const arrayBuffer = await blobRes.arrayBuffer();
                    
                    filesToUploadToNotion.push({
                        filename: item.filename,
                        contentType: blobRes.headers.get('content-type') || 'application/octet-stream',
                        dataBuffer: arrayBuffer,
                        blobUrl: item.blobUrl,
                        isBlob: true
                    });
                }
            }

            // 2. Ekstrak data fisik (buffer) file dari Payload Direct (< 4MB)
            if (uploadedFiles.directFiles) {
                const dFiles = Array.isArray(uploadedFiles.directFiles) ? uploadedFiles.directFiles : [uploadedFiles.directFiles];
                for (const dFile of dFiles) {
                    const buffer = fs.readFileSync(dFile.filepath); // Membaca file lokal dari serverless tmp
                    filesToUploadToNotion.push({
                        filename: dFile.originalFilename || dFile.newFilename || 'upload.bin',
                        contentType: dFile.mimetype || 'application/octet-stream',
                        dataBuffer: buffer,
                        blobUrl: null,
                        isBlob: false
                    });
                }
            }

            // 3. Eksekusi pengunggahan ke server internal Notion
            for (const item of filesToUploadToNotion) {
                // a. Alokasi Slot Notion
                const initRes = await fetch('https://api.notion.com/v1/file_uploads', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${process.env.NOTION_TOKEN}`,
                        'Notion-Version': '2026-03-11',
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ mode: 'single_part', filename: item.filename, content_type: item.contentType })
                });

                if (!initRes.ok) throw new Error(`Gagal alokasi slot Notion untuk "${item.filename}": ${await initRes.text()}`);
                const initData = await initRes.json();

                // b. Unggah fisik ke AWS S3 Notion
                const formData = new FormData();
                const fileBlob = new Blob([item.dataBuffer], { type: item.contentType });
                formData.append('file', fileBlob, item.filename);

                const uploadRes = await fetch(initData.upload_url, {
                    method: 'POST',
                    headers: { 'Authorization': `Bearer ${process.env.NOTION_TOKEN}`, 'Notion-Version': '2026-03-11' },
                    body: formData
                });

                if (!uploadRes.ok) throw new Error(`Gagal transfer S3 Notion "${item.filename}": ${await uploadRes.text()}`);

                // c. Rekam metadata yang sukses
                formattedFiles.push({
                    name: item.filename,
                    type: "file_upload",
                    file_upload: { id: initData.id }
                });

                // d. Hapus jejak sampah di Vercel Blob (Hanya jika file tersebut berasal dari Vercel Blob / > 4MB)
                if (item.isBlob && item.blobUrl) {
                    const { del } = await import('@vercel/blob');
                    await del(item.blobUrl).catch(() => {});
                }
            }
            
            const fieldsData = { 
                rec_id, judul, status, mulai, selesai, harga_sewa, jaminan, keterangan, memo, penyewa_id, property_id, formattedFiles 
            };
            const propertiesData = await buildPropertiesData(notion, targetId, databaseId, fieldsData);

            let targetUrl = '';
            let targetMethod = '';
            let payload = {};

            if (!isCreateMode) {
                targetUrl = `https://api.notion.com/v1/pages/${targetId}`;
                targetMethod = 'PATCH';
                payload = { properties: propertiesData };
            } else {
                targetUrl = `https://api.notion.com/v1/pages`;
                targetMethod = 'POST';
                payload = { parent: { database_id: databaseId }, properties: propertiesData };
            }

            const updateRes = await fetch(targetUrl, {
                method: targetMethod,
                headers: {
                    'Authorization': `Bearer ${process.env.NOTION_TOKEN}`,
                    'Notion-Version': '2026-03-11',
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(payload)
            });

            if (!updateRes.ok) {
                const errText = await updateRes.text();
                throw new Error(`Gagal menyimpan ke Notion: ${errText}`);
            }

            return res.status(200).json({ 
                message: !isCreateMode 
                    ? `Data Kontrak ${type.toUpperCase()} berhasil diperbarui` 
                    : `Data Kontrak ${type.toUpperCase()} baru berhasil disimpan`,
                isAdmin: pin === PIN_ADMIN
            });
        } catch (error) {
            return res.status(500).json({ error: 'Gagal simpan: ' + error.message });
        }
    }

    // 4. HAPUS DATA
    if (req.method === 'DELETE') {
        const pin = bodyFields.pin;
        if (pin !== PIN_ADMIN) return res.status(403).json({ message: 'PIN Hapus Salah! (Hanya PIN Admin yang dapat menghapus data)' });

        try {
            await notion.pages.update({ page_id: targetId, archived: true });
            return res.status(200).json({ message: `Data Kontrak ${type.toUpperCase()} berhasil dihapus` });
        } catch (error) {
            return res.status(500).json({ error: error.message });
        }
    }

    return res.status(405).json({ message: 'Method Not Allowed' });
}
