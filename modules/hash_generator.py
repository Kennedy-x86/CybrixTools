def generate_hash(input_data):
    import hashlib
    md5_hash = hashlib.md5(input_data.encode()).hexdigest()
    sha1_hash = hashlib.sha1(input_data.encode()).hexdigest()
    sha256_hash = hashlib.sha256(input_data.encode()).hexdigest()
    sha512_hash = hashlib.sha512(input_data.encode()).hexdigest()

    return {
        "MD5": md5_hash,
        "SHA1": sha1_hash,
        "SHA256": sha256_hash,
        "SHA512": sha512_hash
    }

def main():
    print("Hash Generator")
    print("==============")
    
    input_data = input("Enter a string: ")
    hashes = generate_hash(input_data)

    print("Hashes:")
    for algo, hash_value in hashes.items():
        print(f"{algo}: {hash_value}")

if __name__ == "__main__":
    main()
    