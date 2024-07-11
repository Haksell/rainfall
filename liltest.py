# return_addr = 0x0804853e
return_addr = 0xb7e6b060
mask = 0xb0000000

result = return_addr & mask

if result == mask:
    print("Address gets caught by the if condition")
else:
    print("Address does not get caught by the if condition")
