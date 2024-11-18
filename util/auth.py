def extract_credentials(request):
    import string
    ALLOWED_PASSWORD_CHARS = set(
        string.ascii_letters + string.digits + "!@#$%^&()-_="
    )
    def percent_decode(encoded_str):
        decoded_chars = []
        i = 0
        length = len(encoded_str)
        while i < length:
            char = encoded_str[i]
            if char == '%':
                if i + 2 >= length:
                    return None
                hex_part = encoded_str[i + 1:i + 3]
                try:
                    decoded_char = chr(int(hex_part, 16))
                except ValueError:
                    return None
                if decoded_char not in ALLOWED_PASSWORD_CHARS:
                    return None

                decoded_chars.append(decoded_char)
                i += 3
            else:
                if char not in ALLOWED_PASSWORD_CHARS:
                    return None
                decoded_chars.append(char)
                i += 1
        return ''.join(decoded_chars)

    try:
        body_str = request.body.decode('utf-8')
    except UnicodeDecodeError as e:
        return None
    pairs = body_str.split('&')
    username = None
    password = None
    for pair in pairs:
        if '=' not in pair:
            continue
        key, value = pair.split('=', 1)
        if key == 'username':
            username = value
        elif key == 'password':
            password = value

    # if username and pass are None
    if not username or not password:
        return None

    if not username.isalnum():
        return None

    decoded_password = percent_decode(password)
    credentials = [username, decoded_password]

    return credentials




def validate_password(password):
    special_characters = {'!', '@', '#', '$', '%', '^', '&', '(', ')', '-', '_', '='}
    if len(password) < 8:
        return False
    password = str(password)
    has_lower = False
    has_upper = False
    has_digit = False
    has_special = False
    valid_characters = True
    for char in password:
        if char.islower():
            has_lower = True
        elif char.isupper():
            has_upper = True
        elif char.isdigit():
            has_digit = True
        elif char in special_characters:
            has_special = True
        else:
            valid_characters = False
            break
    if has_lower and has_upper and has_digit and has_special and valid_characters:
        return True
    else:
        return False











