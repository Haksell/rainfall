# return_addr = 0x0804853e
return_addr = 0xB7E6B060
mask = 0xB0000000

result = return_addr & mask

if result == mask:
    print("Address gets caught by the if condition")
else:
    print("Address does not get caught by the if condition")
