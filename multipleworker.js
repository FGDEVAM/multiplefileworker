// ========================================
// CONFIGURATION & CONSTANTS
// ========================================

const DEFAULT_HOST = "dm.nephobox.com";

// R2 Configuration
const R2_CONFIG = {
  endpoint: "https://a7c795badc3b7f956a5be7a8147aa2b5.r2.cloudflarestorage.com",
  bucketName: "teraboxserver",
  accessKeyId: "054b9389dd038a7c87b0fd204ac30b0c",
  secretAccessKey: "6d82c415b0e0049c1304b33d76e2965c5913fde41f8fc8237d5c547a4e21ce45",
  publicDomain: "https://pub-8273370cf4eb45619bcb8168d5104614.r2.dev",
  region: "auto"
};

// Google Drive Configuration
const GDRIVE_CONFIG = {
  clientId: '672184719028-i709j5ler8ul6al5tm0f56vb2722kp54.apps.googleusercontent.com',
  clientSecret: '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',
  refreshToken: '1//0gDh94F0P0sdWCgYIARAAGBASNwF-L9Irg1h245pWmNRCd0Q4dWwah1iAVDtJZsqCckR40HFE_tHVxYxG-TjSLh7tR3tcibz1SM0',
  folderName: 'TeraBox'
};

// ========================================
// HELPER FUNCTIONS
// ========================================

function getHost(host) {
  return host && host.trim() ? host.trim() : DEFAULT_HOST;
}

function getSize(bytes) {
  if (bytes >= 1073741824) return `${(bytes / 1073741824).toFixed(2)} GB`;
  if (bytes >= 1048576) return `${(bytes / 1048576).toFixed(2)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  return `${bytes} bytes`;
}

function formatDuration(seconds) {
  if (!seconds || seconds <= 0) return "00:00";
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = Math.floor(seconds % 60);
  if (hours > 0) {
    return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  }
  return `${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
}

function getQualityFromHeight(height) {
  if (!height || height <= 0) return "360p";
  if (height >= 2160) return "4K";
  if (height >= 1440) return "2K";
  if (height >= 1080) return "1080p";
  if (height >= 720) return "720p";
  if (height >= 480) return "480p";
  return "360p";
}

function findBetween(content, start, end) {
  const startIndex = content.indexOf(start);
  if (startIndex === -1) return '';
  const beginIndex = startIndex + start.length;
  const endIndex = content.indexOf(end, beginIndex);
  if (endIndex === -1) return '';
  return content.substring(beginIndex, endIndex);
}

function extractShortUrlId(input) {
  try {
    if (!input.includes('://') && !input.includes('/')) {
      return input.startsWith('1') ? input : '1' + input;
    }
    const urlObj = new URL(input);
    if (urlObj.searchParams.has("surl")) {
      const surl = urlObj.searchParams.get("surl");
      return surl.startsWith('1') ? surl : '1' + surl;
    }
    const pathMatch = input.match(/\/s\/([^\/\?&]+)/);
    if (pathMatch) {
      const id = pathMatch[1];
      return id.startsWith('1') ? id : '1' + id;
    }
    const segments = urlObj.pathname.split('/').filter(s => s);
    if (segments.length > 0) {
      const lastSegment = segments[segments.length - 1];
      return lastSegment.startsWith('1') ? lastSegment : '1' + lastSegment;
    }
    return null;
  } catch(e) {
    const cleaned = input.trim();
    return cleaned.startsWith('1') ? cleaned : '1' + cleaned;
  }
}

// ========================================
// R2 UPLOAD FUNCTIONS
// ========================================

async function sha256(message) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hmac(key, message, hex = false) {
  const keyBuffer = typeof key === 'string' ? new TextEncoder().encode(key) : key;
  const msgBuffer = new TextEncoder().encode(message);
  const cryptoKey = await crypto.subtle.importKey(
    "raw", keyBuffer, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", cryptoKey, msgBuffer);
  if (hex) {
    const hashArray = Array.from(new Uint8Array(signature));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }
  return signature;
}

// Check if file already exists in R2 (using public URL)
async function checkR2FileExists(fileName) {
  const { publicDomain } = R2_CONFIG;
  try {
    const response = await fetch(`${publicDomain}/${encodeURIComponent(fileName)}`, {
      method: 'HEAD'
    });
    return response.ok;
  } catch {
    return false;
  }
}

async function uploadToR2(fileBuffer, fileName, contentType = "image/jpeg") {
  const { endpoint, bucketName, accessKeyId, secretAccessKey, publicDomain, region } = R2_CONFIG;
  
  const url = `${endpoint}/${bucketName}/${encodeURIComponent(fileName)}`;
  const date = new Date();
  const amzDate = date.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.slice(0, 8);

  const method = "PUT";
  const canonicalUri = `/${bucketName}/${encodeURIComponent(fileName)}`;
  const canonicalQueryString = "";
  const host = new URL(endpoint).host;
  const canonicalHeaders = `host:${host}\nx-amz-content-sha256:UNSIGNED-PAYLOAD\nx-amz-date:${amzDate}\n`;
  const signedHeaders = "host;x-amz-content-sha256;x-amz-date";
  const payloadHash = "UNSIGNED-PAYLOAD";
  const canonicalRequest = `${method}\n${canonicalUri}\n${canonicalQueryString}\n${canonicalHeaders}\n${signedHeaders}\n${payloadHash}`;

  const algorithm = "AWS4-HMAC-SHA256";
  const credentialScope = `${dateStamp}/${region}/s3/aws4_request`;
  const canonicalRequestHash = await sha256(canonicalRequest);
  const stringToSign = `${algorithm}\n${amzDate}\n${credentialScope}\n${canonicalRequestHash}`;

  const kDate = await hmac(`AWS4${secretAccessKey}`, dateStamp);
  const kRegion = await hmac(kDate, region);
  const kService = await hmac(kRegion, "s3");
  const kSigning = await hmac(kService, "aws4_request");
  const signature = await hmac(kSigning, stringToSign, true);

  const authorizationHeader = `${algorithm} Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 30000);

  try {
    const uploadResponse = await fetch(url, {
      method: "PUT",
      headers: {
        "Authorization": authorizationHeader,
        "x-amz-date": amzDate,
        "x-amz-content-sha256": payloadHash,
        "Content-Type": contentType,
        "Content-Length": fileBuffer.byteLength.toString(),
      },
      body: fileBuffer,
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!uploadResponse.ok) {
      const errorText = await uploadResponse.text();
      throw new Error(`R2 upload failed: ${uploadResponse.status} - ${errorText}`);
    }

    return `${publicDomain}/${encodeURIComponent(fileName)}`;
  } catch (error) {
    clearTimeout(timeoutId);
    if (error.name === 'AbortError') {
      throw new Error('Upload timeout');
    }
    throw error;
  }
}

// ========================================
// GOOGLE DRIVE FUNCTIONS (OPTIMIZED)
// ========================================

let cachedToken = null;
let cachedFolderId = null;
let tokenExpiry = 0;

async function getGDriveAccessToken() {
  if (cachedToken && Date.now() < tokenExpiry) {
    return cachedToken;
  }

  const { clientId, clientSecret, refreshToken } = GDRIVE_CONFIG;
  
  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      refresh_token: refreshToken,
      grant_type: 'refresh_token'
    })
  });

  const data = await response.json();
  cachedToken = data.access_token;
  tokenExpiry = Date.now() + (data.expires_in - 300) * 1000;
  
  return cachedToken;
}

async function getOrCreateGDriveFolder(token) {
  if (cachedFolderId) {
    return cachedFolderId;
  }

  const { folderName } = GDRIVE_CONFIG;
  const headers = { 'Authorization': `Bearer ${token}` };

  const searchResponse = await fetch(
    `https://www.googleapis.com/drive/v3/files?q=name='${folderName}' and mimeType='application/vnd.google-apps.folder' and trashed=false&fields=files(id)`,
    { headers }
  );

  const searchData = await searchResponse.json();
  if (searchData.files && searchData.files.length > 0) {
    cachedFolderId = searchData.files[0].id;
    return cachedFolderId;
  }

  const createResponse = await fetch('https://www.googleapis.com/drive/v3/files?fields=id', {
    method: 'POST',
    headers: { ...headers, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name: folderName,
      mimeType: 'application/vnd.google-apps.folder'
    })
  });

  const createData = await createResponse.json();
  cachedFolderId = createData.id;

  fetch(`https://www.googleapis.com/drive/v3/files/${cachedFolderId}/permissions`, {
    method: 'POST',
    headers: { ...headers, 'Content-Type': 'application/json' },
    body: JSON.stringify({ role: 'reader', type: 'anyone' })
  }).catch(() => {});

  return cachedFolderId;
}

// Check if file exists in GDrive folder
async function checkGDriveFileExists(fileName, token, folderId) {
  try {
    const checkResponse = await fetch(
      `https://www.googleapis.com/drive/v3/files?q=name='${fileName}' and '${folderId}' in parents and trashed=false&fields=files(id)`,
      { headers: { 'Authorization': `Bearer ${token}` } }
    );

    const checkData = await checkResponse.json();
    
    if (checkData.files && checkData.files.length > 0) {
      return checkData.files[0].id;
    }
    return null;
  } catch {
    return null;
  }
}

async function uploadToGDrive(fileBuffer, fileName, contentType, token, folderId) {
  // Check if file already exists (deduplication)
  const existingId = await checkGDriveFileExists(fileName, token, folderId);
  if (existingId) {
    console.log(`File ${fileName} already exists in GDrive, using existing ID`);
    return existingId;
  }

  // File doesn't exist, proceed with upload
  const boundary = '-------314159265358979323846';
  
  const metadata = JSON.stringify({
    name: fileName,
    parents: [folderId]
  });
  
  const metadataHeader = `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n`;
  const fileHeader = `\r\n--${boundary}\r\nContent-Type: ${contentType}\r\n\r\n`;
  const closeDelimiter = `\r\n--${boundary}--`;
  
  const encoder = new TextEncoder();
  const metadataPart = encoder.encode(metadataHeader + metadata + fileHeader);
  const closePart = encoder.encode(closeDelimiter);
  
  const totalLength = metadataPart.length + fileBuffer.byteLength + closePart.length;
  const body = new Uint8Array(totalLength);
  body.set(metadataPart, 0);
  body.set(new Uint8Array(fileBuffer), metadataPart.length);
  body.set(closePart, metadataPart.length + fileBuffer.byteLength);

  const response = await fetch('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': `multipart/related; boundary=${boundary}`
    },
    body: body
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`GDrive upload failed: ${response.status} - ${errorText}`);
  }

  const data = await response.json();
  const fileId = data.id;

  fetch(`https://www.googleapis.com/drive/v3/files/${fileId}/permissions`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ role: 'reader', type: 'anyone' })
  }).catch(() => {});

  return fileId;
}

// ========================================
// NEW: PER-FILE THUMBNAIL UPLOAD FUNCTION
// ========================================

/**
 * Downloads and uploads thumbnail for a specific file
 * Uses fs_id as unique identifier for deduplication
 * 
 * @param {string} thumbnailUrl - Original TeraBox thumbnail URL
 * @param {string} fsId - Unique file system ID from TeraBox
 * @param {string|null} gdriveToken - Pre-fetched GDrive access token
 * @param {string|null} gdriveFolderId - Pre-fetched GDrive folder ID
 * @returns {Object|null} - { r2: url, gdrive_id: id } or null on failure
 */
async function uploadThumbnailForFile(thumbnailUrl, fsId, gdriveToken = null, gdriveFolderId = null) {
  try {
    const fileName = `${fsId}.jpg`;
    const r2PublicUrl = `${R2_CONFIG.publicDomain}/${encodeURIComponent(fileName)}`;

    // Check if already exists in R2
    const existsInR2 = await checkR2FileExists(fileName);
    
    if (existsInR2) {
      // File exists in R2, check GDrive too
      let gdriveId = null;
      if (gdriveToken && gdriveFolderId) {
        gdriveId = await checkGDriveFileExists(fileName, gdriveToken, gdriveFolderId);
      }
      
      console.log(`Thumbnail ${fileName} already exists, returning cached URLs`);
      return {
        r2: r2PublicUrl,
        gdrive_id: gdriveId,
        cached: true
      };
    }

    // File doesn't exist, download thumbnail
    const response = await fetch(thumbnailUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      }
    });
    
    if (!response.ok) {
      throw new Error(`Failed to download thumbnail: ${response.status}`);
    }

    const thumbnailBuffer = await response.arrayBuffer();
    const contentType = response.headers.get('content-type') || 'image/jpeg';

    // Upload to R2 and GDrive in parallel
    const uploadPromises = [
      uploadToR2(thumbnailBuffer, fileName, contentType).catch(err => {
        console.error(`R2 upload failed for ${fileName}:`, err);
        return null;
      })
    ];

    if (gdriveToken && gdriveFolderId) {
      uploadPromises.push(
        uploadToGDrive(thumbnailBuffer, fileName, contentType, gdriveToken, gdriveFolderId).catch(err => {
          console.error(`GDrive upload failed for ${fileName}:`, err);
          return null;
        })
      );
    } else {
      uploadPromises.push(Promise.resolve(null));
    }

    const [r2Url, gDriveFileId] = await Promise.all(uploadPromises);

    return {
      r2: r2Url,
      gdrive_id: gDriveFileId,
      cached: false
    };

  } catch (error) {
    console.error(`Thumbnail upload error for fs_id ${fsId}:`, error);
    return null;
  }
}

// ========================================
// TERA BOX AUTH & API LOGIC
// ========================================

function rc4Encrypt(key, data) {
  const s = [], k = [];
  let result = '';
  const keyLength = key.length;
  for (let i = 0; i < 256; i++) { s[i] = i; k[i] = key.charCodeAt(i % keyLength); }
  for (let i = 0, j = 0; i < 256; i++) {
    j = (j + s[i] + k[i]) % 256;
    [s[i], s[j]] = [s[j], s[i]];
  }
  for (let i = 0, j = 0, c = 0; c < data.length; c++) {
    i = (i + 1) % 256;
    j = (j + s[i]) % 256;
    [s[i], s[j]] = [s[j], s[i]];
    result += String.fromCharCode(data.charCodeAt(c) ^ s[(s[i] + s[j]) % 256]);
  }
  return result;
}

function generateTeraBoxSign(sign1, sign3) {
  const encrypted = rc4Encrypt(sign3, sign1);
  return encodeURIComponent(btoa(encrypted));
}

async function getJsToken(cookie, host = DEFAULT_HOST) {
  try {
    const response = await fetch(`https://${host}/main?category=all`, {
      headers: { "Cookie": cookie, "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" }
    });
    const content = await response.text();
    return findBetween(content, "fn%28%22", "%22%29") || findBetween(content, 'fn("', '")') || findBetween(content, '"jsToken":"', '"') || null;
  } catch { return null; }
}

async function fetchShortUrlInfo(shortUrl, cookie, host = DEFAULT_HOST) {
  try {
    const response = await fetch(`https://${host}/api/shorturlinfo?clienttype=1&root=1&shorturl=${shortUrl}`, {
      headers: { "Cookie": cookie, "User-Agent": "dubox;4.7.1;iPhone16ProMax;ios-iphone;26.0.1;en_IN" }
    });
    const data = await response.json();
    return data.errno === 0 ? { success: true, data } : { success: false };
  } catch { return { success: false }; }
}

async function getFileMetasFromApi(cookie, jsToken, fsIds, host = DEFAULT_HOST) {
  try {
    const fsIdArray = Array.isArray(fsIds) ? fsIds : [fsIds];
    const url = `https://${host}/api/filemetas?dlink=1&target=${encodeURIComponent(JSON.stringify(fsIdArray))}`;
    const response = await fetch(url, {
      headers: { "Cookie": cookie, "User-Agent": "Mozilla/5.0" }
    });
    const data = await response.json();
    return (data.errno === 0 && data.info) ? data.info : null;
  } catch { return null; }
}

async function getMediaMeta(uk, shareid, fs_id, server_time) {
  try {
    const params = new URLSearchParams({
      clienttype: '5',
      uk: uk,
      shareid: shareid,
      fid: fs_id,
      timestamp: server_time
    });

    const metaUrl = `https://www.1024tera.com/share/mediameta?${params.toString()}`;
    const response = await fetch(metaUrl, {
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      },
      signal: AbortSignal.timeout(30000)
    });

    if (response.ok) {
      const meta = await response.json();
      if (meta && meta.errno === 0) {
        return {
          duration: meta.duration || 0,
          quality: getQualityFromHeight(meta.height || 0),
          width: meta.width || 0,
          height: meta.height || 0
        };
      }
    }
  } catch (error) {
    console.error('MediaMeta fetch error:', error);
  }
  return null;
}

// ========================================
// CORE LOGIC WITH PER-FILE THUMBNAIL UPLOAD
// ========================================

async function processMetadata(input, cookie, host = DEFAULT_HOST, uploadThumbs = true) {
  try {
    const shortUrl = extractShortUrlId(input);
    if (!shortUrl) {
      return { error: "Could not extract Short URL ID from input" };
    }

    const [jsToken, shortUrlInfo] = await Promise.all([
      getJsToken(cookie, host),
      fetchShortUrlInfo(shortUrl, cookie, host)
    ]);

    if (!jsToken || !shortUrlInfo.success) {
      return { error: "Failed to fetch file info from TeraBox" };
    }

    const fileList = shortUrlInfo.data.list;
    if (!fileList || fileList.length === 0) {
      return { error: "No files found in link" };
    }

    const fsIds = fileList.map(f => f.fs_id);
    const detailedMetas = await getFileMetasFromApi(cookie, jsToken, fsIds, host);
    
    const metaMap = {};
    if (detailedMetas) detailedMetas.forEach(m => metaMap[m.fs_id] = m);

    // Pre-initialize GDrive token and folder ID ONCE for all uploads
    let gdriveToken = null;
    let gdriveFolderId = null;
    
    if (uploadThumbs) {
      try {
        gdriveToken = await getGDriveAccessToken();
        gdriveFolderId = await getOrCreateGDriveFolder(gdriveToken);
      } catch (e) {
        console.error('Failed to initialize GDrive:', e);
      }
    }

    // Get additional info for accurate metadata
    const uk = shortUrlInfo.data.uk || '';
    const shareid = shortUrlInfo.data.shareid || shortUrlInfo.data.share_id || '';
    const server_time = shortUrlInfo.data.server_time || Math.floor(Date.now() / 1000);

    // Track upload statistics
    let thumbnailStats = {
      uploaded: 0,
      cached: 0,
      failed: 0,
      skipped: 0
    };

    // Process files with individual thumbnail uploads
    const resultList = await Promise.all(fileList.map(async (file) => {
      const meta = metaMap[file.fs_id] || {};
      const isDir = file.isdir === 1 || file.isdir === "1";
      const filename = file.server_filename;
      const size = parseInt(file.size || 0);
      
      const ext = filename.split('.').pop().toLowerCase();
      let type = isDir ? "folder" : "file";
      const videoFormats = ["mp4", "mkv", "avi", "mov", "wmv", "flv", "webm", "m4v", "3gp"];
      const imageFormats = ["jpg", "jpeg", "png", "gif", "bmp", "webp"];
      if (videoFormats.includes(ext)) type = "video";
      else if (imageFormats.includes(ext)) type = "image";

      const fileObj = {
        id: file.fs_id,
        filename: filename,
        type: type,
        size_bytes: size,
        size_formatted: getSize(size),
        created_time: new Date(parseInt(file.server_ctime) * 1000).toISOString(),
      };

      // For folders, add child count if available and path
      if (isDir) {
        fileObj.path = file.path || `/${filename}`;
        // Folders don't have thumbnails - skip thumbnail upload
        thumbnailStats.skipped++;
      }

      // Upload thumbnail for videos and images (not folders)
      if (uploadThumbs && (type === "video" || type === "image")) {
        const thumbnail = meta.thumbs?.url3 || meta.thumbs?.url2 || meta.thumbs?.url1 || 
                         file.thumbs?.url3 || file.thumbs?.url2 || file.thumbs?.url1 || null;
        
        if (thumbnail) {
          const uploadResult = await uploadThumbnailForFile(
            thumbnail, 
            file.fs_id, 
            gdriveToken, 
            gdriveFolderId
          );
          
          if (uploadResult) {
            if (uploadResult.r2) {
              fileObj.thumbnail = uploadResult.r2;
            }
            if (uploadResult.gdrive_id) {
              fileObj.gdrive_id = uploadResult.gdrive_id;
            }
            
            if (uploadResult.cached) {
              thumbnailStats.cached++;
            } else {
              thumbnailStats.uploaded++;
            }
          } else {
            thumbnailStats.failed++;
          }
        } else {
          thumbnailStats.skipped++;
        }
      }

      // For videos, fetch accurate metadata from mediameta API
      if (type === "video") {
        const videoMeta = await getMediaMeta(uk, shareid, file.fs_id, server_time);
        
        if (videoMeta) {
          fileObj.duration_seconds = videoMeta.duration;
          fileObj.duration_formatted = formatDuration(videoMeta.duration);
          fileObj.resolution = videoMeta.quality;
          fileObj.width = videoMeta.width;
          fileObj.height = videoMeta.height;
        } else {
          fileObj.duration_seconds = meta.duration || 0;
          fileObj.duration_formatted = formatDuration(meta.duration || 0);
          fileObj.resolution = getQualityFromHeight(meta.height);
          fileObj.width = meta.width;
          fileObj.height = meta.height;
        }
      }

      return fileObj;
    }));

    // Separate files and folders for better organization
    const files = resultList.filter(f => f.type !== "folder");
    const folders = resultList.filter(f => f.type === "folder");

    return {
      status: "success",
      short_url_id: shortUrl,
      share_id: shortUrlInfo.data.shareid,
      uk: shortUrlInfo.data.uk,
      total_count: resultList.length,
      file_count: files.length,
      folder_count: folders.length,
      thumbnail_stats: thumbnailStats,
      files: files,
      folders: folders.length > 0 ? folders : undefined
    };

  } catch (error) {
    return { error: "Server Error: " + error.message };
  }
}

// ========================================
// HANDLER
// ========================================

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Content-Type": "application/json"
  };
}

export default {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders() });
    }

    const url = new URL(request.url);
    const teraUrl = url.searchParams.get("url");
    const cookie = url.searchParams.get("cookie");
    const customHost = url.searchParams.get("host");
    const uploadThumbs = url.searchParams.get("upload_thumbnails") !== "false";

    if (!teraUrl || !cookie) {
      return new Response(JSON.stringify({ 
        error: "Missing 'url' or 'cookie' parameters",
        usage: "?url=<terabox_url_or_id>&cookie=<your_cookie>&upload_thumbnails=<true|false>&host=<optional>"
      }), {
        status: 400,
        headers: corsHeaders()
      });
    }

    const apiHost = getHost(customHost);
    const result = await processMetadata(teraUrl, cookie, apiHost, uploadThumbs);
    
    return new Response(JSON.stringify(result, null, 2), {
      status: result.error ? 400 : 200,
      headers: corsHeaders()
    });
  }
};
