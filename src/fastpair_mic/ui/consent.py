def request_consent(device_name: str, address: str) -> bool:
    """
    Ask the user for explicit consent before connecting to a target.

    The user must type exactly:
        I accept
    """

    print()
    print("=" * 60)
    print("WHISPER PAIR SECURITY DEMONSTRATION")
    print("=" * 60)
    print()
    print(f"Target:  {device_name}")
    print(f"Address: {address}")
    print()
    print("WARNING")
    print("-------")
    print(
        "This demonstration will connect to the selected Bluetooth "
        "device and perform a non-destructive security assessment."
    )
    print()
    print(
        "Only continue if you own the device or have explicit "
        "permission to test it."
    )
    print()
    print('Type "I accept" to continue.')
    print("Type anything else to cancel.")
    print()

    response = input("> ").strip()

    return response == "I accept"
