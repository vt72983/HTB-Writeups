target_numbers_str = "1152 1344 1056 1968 1728 816 1648 784 1584 816 1728 1520 1840 1664 784 1632 1856 1520 1728 816 1632 1856 1520 784 1760 1840 1824 816 1584 1856 784 1776 1760 528 528 2000"
target_numbers = [int(n) for n in target_numbers_str.split()]
password = ""
for number in target_numbers:
    original_char_code = number 
    password += chr(original_char_code)
print(password)
