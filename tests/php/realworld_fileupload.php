<?php
/**
 * Real-world Unrestricted File Upload test file for Kunlun-M scanner.
 * Simulates an avatar upload and document management system.
 */

class UploadController {
    private $uploadDir;
    private $maxFileSize = 5242880; // 5MB

    public function __construct() {
        $this->uploadDir = __DIR__ . '/uploads/';
        if (!is_dir($this->uploadDir)) {
            mkdir($this->uploadDir, 0755, true);
        }
    }

    /**
     * VULN: Unrestricted file upload - no extension check, no MIME type check.
     * Attacker can upload .php webshell files.
     */
    public function uploadAvatar() {
        if (!isset($_FILES['avatar'])) {
            echo json_encode(['error' => 'No file uploaded']);
            return;
        }

        $file = $_FILES['avatar'];
        if ($file['error'] !== UPLOAD_ERR_OK) {
            echo json_encode(['error' => 'Upload error code: ' . $file['error']]);
            return;
        }

        // Only checks file size, no extension or content validation
        if ($file['size'] > $this->maxFileSize) {
            echo json_encode(['error' => 'File too large']);
            return;
        }

        $filename = basename($file['name']);
        $destPath = $this->uploadDir . uniqid() . '_' . $filename;
        move_uploaded_file($file['tmp_name'], $destPath);

        echo json_encode([
            'success'  => true,
            'filepath' => $destPath,
            'filename' => $filename,
        ]);
        // VULN: No extension check - .php shells can be uploaded and executed
    }

    /**
     * VULN: Unrestricted file upload - MIME type check only (easily bypassed).
     * Attacker can spoof Content-Type header.
     */
    public function uploadDocument() {
        if (!isset($_FILES['document'])) {
            echo json_encode(['error' => 'No file uploaded']);
            return;
        }

        $file = $_FILES['document'];
        if ($file['error'] !== UPLOAD_ERR_OK) {
            echo json_encode(['error' => 'Upload failed']);
            return;
        }

        // Only checking MIME type - trivially spoofed
        $allowedMimes = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf'];
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $detectedMime = $finfo->file($file['tmp_name']);

        // But we don't actually enforce it properly - the check is after we've already
        // accepted the filename without extension restriction
        $filename = basename($file['name']);
        $destPath = $this->uploadDir . 'docs/' . $filename;

        // VULN: creating directory but not checking extension
        $docDir = $this->uploadDir . 'docs/';
        if (!is_dir($docDir)) {
            mkdir($docDir, 0755, true);
        }

        move_uploaded_file($file['tmp_name'], $destPath);

        echo json_encode([
            'success' => true,
            'mime'    => $detectedMime,
            'path'    => $destPath,
        ]);
        // VULN: MIME check exists but extension is not validated - shell.php still gets through
    }

    /**
     * VULN: Double extension bypass not handled.
     * Filename like "shell.php.jpg" could bypass naive checks.
     */
    public function uploadMedia() {
        if (!isset($_FILES['media'])) {
            echo json_encode(['error' => 'No file']);
            return;
        }

        $file = $_FILES['media'];
        $filename = basename($file['name']);
        // Naive check: just looks at the last extension
        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        $allowed = ['jpg', 'jpeg', 'png', 'gif'];

        if (in_array($ext, $allowed)) {
            $destPath = $this->uploadDir . 'media/' . $filename;
            move_uploaded_file($file['tmp_name'], $destPath);
            echo json_encode(['success' => true, 'path' => $destPath]);
        } else {
            echo json_encode(['error' => 'Extension not allowed']);
        }
        // VULN: "shell.php.jpg" passes but Apache may parse as PHP if misconfigured
        // Also original filename preserved - predictable paths
    }

    /**
     * SAFE: Strict extension whitelist + random filename + content validation.
     */
    public function safeUploadAvatar() {
        if (!isset($_FILES['avatar'])) {
            echo json_encode(['error' => 'No file uploaded']);
            return;
        }

        $file = $_FILES['avatar'];
        if ($file['error'] !== UPLOAD_ERR_OK) {
            echo json_encode(['error' => 'Upload error']);
            return;
        }

        // 1. Validate file size
        if ($file['size'] > $this->maxFileSize) {
            echo json_encode(['error' => 'File too large (max 5MB)']);
            return;
        }

        // 2. Whitelist allowed extensions
        $allowedExtensions = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
        $originalName = basename($file['name']);
        $ext = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));

        if (!in_array($ext, $allowedExtensions, true)) {
            echo json_encode(['error' => 'File type not allowed']);
            return;
        }

        // 3. Validate actual MIME type with finfo
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mimeMap = [
            'jpg'  => 'image/jpeg',
            'jpeg' => 'image/jpeg',
            'png'  => 'image/png',
            'gif'  => 'image/gif',
            'webp' => 'image/webp',
        ];
        $detectedMime = $finfo->file($file['tmp_name']);
        if ($detectedMime !== ($mimeMap[$ext] ?? null)) {
            echo json_encode(['error' => 'MIME type mismatch']);
            return;
        }

        // 4. Generate random filename to prevent path guessing
        $newFilename = bin2hex(random_bytes(16)) . '.' . $ext;
        $destPath = $this->uploadDir . 'avatars/' . $newFilename;

        $avatarDir = $this->uploadDir . 'avatars/';
        if (!is_dir($avatarDir)) {
            mkdir($avatarDir, 0755, true);
        }

        move_uploaded_file($file['tmp_name'], $destPath);

        echo json_encode([
            'success'  => true,
            'filename' => $newFilename,
            'path'     => $destPath,
        ]);
        // Safe: extension whitelist + MIME validation + random filename
    }

    /**
     * SAFE: Image content verification using getimagesize().
     */
    public function safeUploadMedia() {
        if (!isset($_FILES['media'])) {
            echo json_encode(['error' => 'No file']);
            return;
        }

        $file = $_FILES['media'];

        // Verify it's actually an image
        $imageInfo = @getimagesize($file['tmp_name']);
        if ($imageInfo === false) {
            echo json_encode(['error' => 'Not a valid image']);
            return;
        }

        $allowedTypes = [IMAGETYPE_JPEG, IMAGETYPE_PNG, IMAGETYPE_GIF, IMAGETYPE_WEBP];
        if (!in_array($imageInfo[2], $allowedTypes)) {
            echo json_encode(['error' => 'Image type not allowed']);
            return;
        }

        // Use random filename with correct extension
        $extensions = [
            IMAGETYPE_JPEG => 'jpg',
            IMAGETYPE_PNG  => 'png',
            IMAGETYPE_GIF  => 'gif',
            IMAGETYPE_WEBP => 'webp',
        ];
        $ext = $extensions[$imageInfo[2]];
        $newFilename = bin2hex(random_bytes(16)) . '.' . $ext;
        $destPath = $this->uploadDir . 'media/' . $newFilename;

        move_uploaded_file($file['tmp_name'], $destPath);

        echo json_encode(['success' => true, 'filename' => $newFilename]);
        // Safe: getimagesize() verifies actual image content
    }
}

// --- Routing ---
if (php_sapi_name() !== 'cli') {
    $controller = new UploadController();
    $action = $_POST['action'] ?? $_GET['action'] ?? 'uploadAvatar';
    if (method_exists($controller, $action)) {
        $controller->$action();
    }
}
