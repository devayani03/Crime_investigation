def decode_key(text):
    # Function to decode a registry key text by replacing non-ASCII characters with a placeholder for malware detection
    return ''.join([i if ord(i) < 128 else '<?>' for i in text])


def big_endian(data):
    # Function to convert little-endian hex-encoded registry data to big-endian for analysis
    big = ""
    for i in range(0, len(data), 4):
        big += data[i+2:i+4]  # Swap the position of bytes for registry analysis
        big += data[i:i+2]
    return big


def parse_date(d):
    # Function to parse a hex-encoded Windows timestamp from the registry to a human-readable date for malware analysis
    d = big_endian(d)
    # Extracting individual components from the hex string for timestamp analysis
    year = int(d[0:4], 16)
    month = int(d[4:8], 16)
    day = int(d[12:16], 16)
    hour = int(d[16:20], 16)
    minutes = int(d[20:24], 16)
    seconds = int(d[24:28], 16)
    # Formatting the date string with zero-padding for clarity in malware detection
    return str(year) + "-" + pad(month) + "-" + pad(day) + " " + pad(hour) + ":" + pad(minutes) + ":" + pad(seconds)


def pad(data):
    # Function to add zero-padding to a single-digit number for improved readability in malware timestamp analysis
    if len(str(data)) != 2:
        return "0" + str(data)
    return str(data)


def hex_windows_to_date(dt):
    # Function to convert a hex-encoded Windows timestamp from the registry to a human-readable date using NTFS timestamp format
    import struct
    from binascii import unhexlify
    from datetime import datetime, timedelta

    # Unpack the hex string to an integer representing the NTFS timestamp for malware detection
    nt_timestamp = struct.unpack("<Q", unhexlify(dt))[0]
    
    # Define the epoch for NTFS timestamps (January 1, 1601) for malware analysis
    epoch = datetime(1601, 1, 1, 0, 0, 0)
    
    # Calculate the datetime by adding microseconds to the epoch for malware timestamp analysis
    nt_datetime = epoch + timedelta(microseconds=nt_timestamp / 10)

    # Format the datetime as a string and return for malware detection purposes
    return nt_datetime.strftime("%c")
