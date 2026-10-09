import os

BINARY_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.ico', '.pdf', '.zip', '.tar', '.gz',
    '.tgz', '.bz2', '.7z', '.exe', '.dll', '.so', '.dylib', '.bin', '.iso',
    '.woff', '.woff2', '.ttf', '.eot', '.mp3', '.mp4', '.avi', '.mov', '.sqlite',
    '.db', '.pyc', '.class', '.o', '.a'
}

def is_binary_file(file_path: str, max_check_bytes: int = 8192) -> bool:
    """
    Check if a file is binary by extension or by scanning initial bytes for null characters.
    """
    _, ext = os.path.splitext(file_path.lower())
    if ext in BINARY_EXTENSIONS:
        return True

    try:
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            return False
            
        with open(file_path, 'rb') as f:
            chunk = f.read(max_check_bytes)
            if b'\x00' in chunk:
                return True
            # Try decoding as utf-8 or ascii
            try:
                chunk.decode('utf-8')
            except UnicodeDecodeError:
                # If high proportion of non-printable characters, consider binary
                non_printable = sum(1 for b in chunk if b < 32 and b not in (9, 10, 13))
                if len(chunk) > 0 and (non_printable / len(chunk)) > 0.3:
                    return True
        return False
    except Exception:
        return True
