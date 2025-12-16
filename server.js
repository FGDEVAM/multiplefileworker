const express = require('express');
const fetch = require('node-fetch');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// ========================================
// CONFIGURATION
// ========================================

const DEFAULT_HOST = "dm.nephobox.com";

const R2_CONFIG = {
  endpoint: "https://a7c795badc3b7f956a5be7a8147aa2b5.r2.cloudflarestorage.com",
  bucketName: "teraboxserver",
  accessKeyId: "054b9389dd038a7c87b0fd204ac30b0c",
  secretAccessKey: "6d82c415b0e0049c1304b33d76e2965c5913fde41f8fc8237d5c547a4e21ce45",
  publicDomain: "https://pub-8273370cf4eb45619bcb8168d5104614.r2.dev",
  region: "auto"
};

const GDRIVE_CONFIG = {
  clientId: '672184719028-i709j5ler8ul6al5tm0f56vb2722kp54.apps.googleusercontent.com',
  clientSecret: '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',
  refreshToken: '1//0gDh94F0P0sdWCgYIARAAGBASNwF-L9Irg1h245pWmNRCd0Q4dWwah1iAVDtJZsqCckR40HFE_tHVxYxG-TjSLh7tR3tcibz1SM0',
  folderName: 'TeraBox'
};

// Token cache
let cachedToken = null;
let cachedFolderId = null;
let tokenExpiry = 0;

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
    return `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
  }
  return `${String(minutes).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
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
  } catch (e) {
    const cleaned = input.trim();
    return cleaned.startsWith('1') ? cleaned : '1' + cleaned;
  }
}

function extractThumbnailUrl(file, meta) {
  const urls = [
    meta?.thumbs?.url3, meta?.thumbs?.url2, meta?.thumbs?.url1,
    meta?.thumbs?.icon, meta?.thumb, meta?.thumbnail,
    file?.thumbs?.url3, file?.thumbs?.url2, file?.thumbs?.url1,
    file?.thumbs?.icon, file?.thumb, file?.thumbnail
  ];
  for (const url of urls) {
    if (url && typeof url === 'string' && url.startsWith('http')) return url;
  }
  return null;
}

// ========================================
// CRYPTO FUNCTIONS (Node.js version)
// ========================================

function hmacSha256(key, data) {
  return crypto.createHmac('sha256', key).update(data).digest();
}

function sha256Hex(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

// ========================================
// R2 UPLOAD FUNCTIONS
// ========================================

async function checkR2FileExists(fileName) {
  try {
    const response = await fetch(`${R2_CONFIG.publicDomain}/${encodeURIComponent(fileName)}`, {
      method: 'HEAD'
    });
    return response.ok;
  } catch {
    return false;
  }
}

async function uploadToR2(buffer, fileName, contentType = "image/jpeg") {
  const { endpoint, bucketName, accessKeyId, secretAccessKey, publicDomain, region } = R2_CONFIG;
  
  const url = `${endpoint}/${bucketName}/${encodeURIComponent(fileName)}`;
  const date = new Date();
  const amzDate = date.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.slice(0, 8);

  const canonicalUri = `/${bucketName}/${encodeURIComponent(fileName)}`;
  const host = new URL(endpoint).host;
  const canonicalHeaders = `host:${host}\nx-amz-content-sha256:UNSIGNED-PAYLOAD\nx-amz-date:${amzDate}\n`;
  const signedHeaders = "host;x-amz-content-sha256;x-amz-date";
  const canonicalRequest = `PUT\n${canonicalUri}\n\n${canonicalHeaders}\n${signedHeaders}\nUNSIGNED-PAYLOAD`;

  const credentialScope = `${dateStamp}/${region}/s3/aws4_request`;
  const stringToSign = `AWS4-HMAC-SHA256\n${amzDate}\n${credentialScope}\n${sha256Hex(canonicalRequest)}`;

  const kDate = hmacSha256(`AWS4${secretAccessKey}`, dateStamp);
  const kRegion = hmacSha256(kDate, region);
  const kService = hmacSha256(kRegion, "s3");
  const kSigning = hmacSha256(kService, "aws4_request");
  const signature = hmacSha256(kSigning, stringToSign).toString('hex');

  const response = await fetch(url, {
    method: "PUT",
    headers: {
      "Authorization": `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
      "x-amz-date": amzDate,
      "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
      "Content-Type": contentType,
      "Content-Length": buffer.length.toString()
    },
    body: buffer
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`R2 upload failed: ${response.status} - ${errorText}`);
  }

  return `${publicDomain}/${encodeURIComponent(fileName)}`;
}

// ========================================
// GOOGLE DRIVE FUNCTIONS
// ========================================

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
  
  if (!data.access_token) {
    throw new Error('Failed to get GDrive access token');
  }
  
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

  // Search for existing folder
  const searchResponse = await fetch(
    `https://www.googleapis.com/drive/v3/files?q=name='${folderName}' and mimeType='application/vnd.google-apps.folder' and trashed=false&fields=files(id)`,
    { headers }
  );

  const searchData = await searchResponse.json();
  if (searchData.files && searchData.files.length > 0) {
    cachedFolderId = searchData.files[0].id;
    return cachedFolderId;
  }

  // Create new folder
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

  // Make folder public (fire and forget)
  fetch(`https://www.googleapis.com/drive/v3/files/${cachedFolderId}/permissions`, {
    method: 'POST',
    headers: { ...headers, 'Content-Type': 'application/json' },
    body: JSON.stringify({ role: 'reader', type: 'anyone' })
  }).catch(() => {});

  return cachedFolderId;
}

async function checkGDriveFileExists(fileName, token, folderId) {
  try {
    const response = await fetch(
      `https://www.googleapis.com/drive/v3/files?q=name='${fileName}' and '${folderId}' in parents and trashed=false&fields=files(id)`,
      { headers: { 'Authorization': `Bearer ${token}` } }
    );

    const data = await response.json();
    
    if (data.files && data.files.length > 0) {
      return data.files[0].id;
    }
    return null;
  } catch {
    return null;
  }
}

async function uploadToGDrive(buffer, fileName, contentType, token, folderId) {
  // Check if already exists
  const existingId = await checkGDriveFileExists(fileName, token, folderId);
  if (existingId) {
    console.log(`File ${fileName} already exists in GDrive, using existing ID`);
    return existingId;
  }

  const boundary = '-------314159265358979323846';
  const metadata = JSON.stringify({ name: fileName, parents: [folderId] });
  
  const body = Buffer.concat([
    Buffer.from(`--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${metadata}\r\n--${boundary}\r\nContent-Type: ${contentType}\r\n\r\n`),
    buffer,
    Buffer.from(`\r\n--${boundary}--`)
  ]);

  const response = await fetch('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': `multipart/related; boundary=${boundary}`
    },
    body
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`GDrive upload failed: ${response.status} - ${errorText}`);
  }

  const data = await response.json();
  const fileId = data.id;

  // Make file public (fire and forget)
  fetch(`https://www.googleapis.com/drive/v3/files/${fileId}/permissions`, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ role: 'reader', type: 'anyone' })
  }).catch(() => {});

  return fileId;
}

// ========================================
// THUMBNAIL UPLOAD FUNCTION
// ========================================

async function uploadThumbnailForFile(thumbnailUrl, fsId, gdriveToken = null, gdriveFolderId = null) {
  try {
    const fileName = `${fsId}.jpg`;
    const r2PublicUrl = `${R2_CONFIG.publicDomain}/${encodeURIComponent(fileName)}`;

    // Check if already exists in R2
    const existsInR2 = await checkR2FileExists(fileName);
    
    if (existsInR2) {
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

    // Download thumbnail
    const response = await fetch(thumbnailUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Referer': 'https://www.terabox.com/'
      }
    });
    
    if (!response.ok) {
      throw new Error(`Failed to download thumbnail: ${response.status}`);
    }

    const arrayBuffer = await response.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);
    
    if (buffer.length < 100) {
      throw new Error('Invalid thumbnail size');
    }
    
    const contentType = response.headers.get('content-type') || 'image/jpeg';

    // Upload to R2 and GDrive in parallel
    const uploadPromises = [
      uploadToR2(buffer, fileName, contentType).catch(err => {
        console.error(`R2 upload failed for ${fileName}:`, err.message);
        return null;
      })
    ];

    if (gdriveToken && gdriveFolderId) {
      uploadPromises.push(
        uploadToGDrive(buffer, fileName, contentType, gdriveToken, gdriveFolderId).catch(err => {
          console.error(`GDrive upload failed for ${fileName}:`, err.message);
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
    console.error(`Thumbnail upload error for fs_id ${fsId}:`, error.message);
    return null;
  }
}

// ========================================
// TERABOX API FUNCTIONS
// ========================================

async function getJsToken(cookie, host = DEFAULT_HOST) {
  try {
    const response = await fetch(`https://${host}/main?category=all`, {
      headers: { 
        "Cookie": cookie, 
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" 
      }
    });
    const content = await response.text();
    return findBetween(content, "fn%28%22", "%22%29") || 
           findBetween(content, 'fn("', '")') || 
           findBetween(content, '"jsToken":"', '"') || null;
  } catch { 
    return null; 
  }
}

async function fetchShortUrlInfo(shortUrl, cookie, host = DEFAULT_HOST) {
  try {
    const response = await fetch(`https://${host}/api/shorturlinfo?clienttype=1&root=1&shorturl=${shortUrl}`, {
      headers: { 
        "Cookie": cookie, 
        "User-Agent": "dubox;4.7.1;iPhone16ProMax;ios-iphone;26.0.1;en_IN" 
      }
    });
    const data = await response.json();
    return data.errno === 0 ? { success: true, data } : { success: false, errno: data.errno };
  } catch (e) { 
    return { success: false, error: e.message }; 
  }
}

async function getFileMetasFromApi(cookie, jsToken, fsIds, host = DEFAULT_HOST) {
  try {
    const fsIdArray = Array.isArray(fsIds) ? fsIds : [fsIds];
    const url = `https://${host}/api/filemetas?dlink=1&thumb=1&target=${encodeURIComponent(JSON.stringify(fsIdArray))}`;
    const response = await fetch(url, {
      headers: { 
        "Cookie": cookie, 
        "User-Agent": "Mozilla/5.0" 
      }
    });
    const data = await response.json();
    return (data.errno === 0 && data.info) ? data.info : null;
  } catch { 
    return null; 
  }
}

async function getMediaMeta(uk, shareid, fs_id, server_time) {
  try {
    const params = new URLSearchParams({
      clienttype: '5',
      uk: String(uk),
      shareid: String(shareid),
      fid: String(fs_id),
      timestamp: String(server_time)
    });

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);

    const response = await fetch(`https://www.1024tera.com/share/mediameta?${params.toString()}`, {
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      },
      signal: controller.signal
    });

    clearTimeout(timeoutId);

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
    // Silently fail for media meta
  }
  return null;
}

// ========================================
// MAIN PROCESSING FUNCTION
// ========================================

async function processMetadata(input, cookie, host = DEFAULT_HOST, uploadThumbs = true) {
  const startTime = Date.now();
  
  try {
    const shortUrl = extractShortUrlId(input);
    if (!shortUrl) {
      return { error: "Could not extract Short URL ID from input" };
    }

    console.log(`Processing: ${shortUrl}`);

    const [jsToken, shortUrlInfo] = await Promise.all([
      getJsToken(cookie, host),
      fetchShortUrlInfo(shortUrl, cookie, host)
    ]);

    if (!shortUrlInfo.success) {
      return { 
        error: "Failed to fetch file info from TeraBox",
        details: shortUrlInfo.errno ? `Error code: ${shortUrlInfo.errno}` : shortUrlInfo.error
      };
    }

    const fileList = shortUrlInfo.data.list;
    if (!fileList || fileList.length === 0) {
      return { error: "No files found in link" };
    }

    const fsIds = fileList.map(f => f.fs_id);
    const detailedMetas = await getFileMetasFromApi(cookie, jsToken, fsIds, host);
    
    const metaMap = {};
    if (detailedMetas) detailedMetas.forEach(m => metaMap[m.fs_id] = m);

    // Initialize GDrive
    let gdriveToken = null;
    let gdriveFolderId = null;
    
    if (uploadThumbs) {
      try {
        gdriveToken = await getGDriveAccessToken();
        gdriveFolderId = await getOrCreateGDriveFolder(gdriveToken);
        console.log('GDrive initialized successfully');
      } catch (e) {
        console.error('Failed to initialize GDrive:', e.message);
      }
    }

    const uk = shortUrlInfo.data.uk || '';
    const shareid = shortUrlInfo.data.shareid || shortUrlInfo.data.share_id || '';
    const server_time = shortUrlInfo.data.server_time || Math.floor(Date.now() / 1000);

    // Track statistics
    const thumbnailStats = {
      uploaded: 0,
      cached: 0,
      failed: 0,
      skipped: 0
    };

    // Process files
    const resultList = await Promise.all(fileList.map(async (file) => {
      const meta = metaMap[file.fs_id] || {};
      const isDir = file.isdir === 1 || file.isdir === "1";
      const filename = file.server_filename;
      const size = parseInt(file.size || 0);
      
      const ext = filename.split('.').pop()?.toLowerCase() || '';
      let type = isDir ? "folder" : "file";
      const videoFormats = ["mp4", "mkv", "avi", "mov", "wmv", "flv", "webm", "m4v", "3gp"];
      const imageFormats = ["jpg", "jpeg", "png", "gif", "bmp", "webp"];
      if (videoFormats.includes(ext)) type = "video";
      else if (imageFormats.includes(ext)) type = "image";

      const fileObj = {
        id: String(file.fs_id),
        filename: filename,
        type: type,
        size_bytes: size,
        size_formatted: getSize(size),
        created_time: new Date(parseInt(file.server_ctime) * 1000).toISOString(),
      };

      // Handle folders
      if (isDir) {
        fileObj.path = file.path || `/${filename}`;
        fileObj.has_contents = true;
        thumbnailStats.skipped++;
        return fileObj;
      }

      // Upload thumbnail for videos and images
      if (uploadThumbs && (type === "video" || type === "image")) {
        const thumbnail = extractThumbnailUrl(file, meta);
        
        if (thumbnail) {
          console.log(`Uploading thumbnail for: ${file.fs_id}`);
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
              console.log(`  Cached: ${file.fs_id}`);
            } else {
              thumbnailStats.uploaded++;
              console.log(`  Uploaded: ${file.fs_id}`);
            }
          } else {
            thumbnailStats.failed++;
            fileObj.thumbnail_fallback = thumbnail;
            console.log(`  Failed: ${file.fs_id}`);
          }
        } else {
          thumbnailStats.skipped++;
        }
      }

      // For videos, fetch accurate metadata
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
          if (meta.width) fileObj.width = meta.width;
          if (meta.height) fileObj.height = meta.height;
        }
      }

      return fileObj;
    }));

    // Separate files and folders
    const files = resultList.filter(f => f.type !== "folder");
    const folders = resultList.filter(f => f.type === "folder");

    const processingTime = Date.now() - startTime;
    console.log(`Completed in ${processingTime}ms`);

    const response = {
      status: "success",
      short_url_id: shortUrl,
      share_id: shortUrlInfo.data.shareid,
      uk: shortUrlInfo.data.uk,
      total_count: resultList.length,
      file_count: files.length,
      folder_count: folders.length,
      processing_time_ms: processingTime,
      thumbnail_stats: thumbnailStats,
      files: files
    };

    if (folders.length > 0) {
      response.folders = folders;
    }

    return response;

  } catch (error) {
    console.error('Processing error:', error);
    return { error: "Server Error: " + error.message };
  }
}

// ========================================
// API ENDPOINTS
// ========================================

// Main API endpoint
app.get('/api', async (req, res) => {
  const { url: teraUrl, cookie, host, upload_thumbnails } = req.query;

  if (!teraUrl || !cookie) {
    return res.status(400).json({
      error: "Missing 'url' or 'cookie' parameters",
      usage: {
        endpoint: "/api",
        params: {
          url: "TeraBox URL or short ID (required)",
          cookie: "Your TeraBox cookie (required)",
          upload_thumbnails: "true (default) | false",
          host: "Custom TeraBox host (optional)"
        },
        example: "/api?url=https://terabox.com/s/1xxx&cookie=YOUR_COOKIE"
      }
    });
  }

  const apiHost = getHost(host);
  const uploadThumbs = upload_thumbnails !== "false";
  
  const result = await processMetadata(teraUrl, cookie, apiHost, uploadThumbs);
  
  res.status(result.error ? 400 : 200).json(result);
});

// Health check endpoint (for UptimeRobot)
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Root endpoint - API info
app.get('/', (req, res) => {
  res.json({
    name: "TeraBox Metadata API",
    version: "2.0.0",
    endpoints: {
      "GET /api": {
        description: "Get metadata and upload thumbnails",
        params: {
          url: "TeraBox URL (required)",
          cookie: "TeraBox cookie (required)",
          upload_thumbnails: "true | false (default: true)",
          host: "Custom host (optional)"
        }
      },
      "GET /health": {
        description: "Health check for UptimeRobot"
      }
    },
    example: "/api?url=https://terabox.com/s/1xxxxx&cookie=YOUR_COOKIE"
  });
});

// ========================================
// START SERVER
// ========================================

const PORT = process.env.PORT || 3000;

app.listen(PORT, '0.0.0.0', () => {
  console.log(`
╔════════════════════════════════════════╗
║   TeraBox Metadata API Started!        ║
║   Port: ${PORT}                             ║
║   Time: ${new Date().toISOString()}   ║
╚════════════════════════════════════════╝
  `);
});
