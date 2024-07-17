letters={
    "1000111": "A",
    "1110010": "B",
    "0011101": "C",
    "1010011": 'D',

    "1010110": "E",
    "0011011": "F",
    "0110101": "G",

    "1101001": "H",
    "1001101": "I",
    "0010111": "J",
    "0011110": "K",
    "1100101": "L",

    "0111001": "M",
    "1011001": "N",
    "1110001": "O",
    "0101101": "P",
    "0101110": 'Q',
    "1010101": "R",

    "1001011": "S",
    "1110100": "T",
    "1001110": "U",
    "0111100": "V",
    "0100111": "W",
    "0111010": "X",
    "0101011": "Y",
    "1100011": "Z",
    "1011100": " ",

    "1111000": "",
    "0110110": "FIGS",
    "1011010": "LTRS",
}

figures={
    "1010011": '$',
    "1000111": "-",
    "1110001": "9",
    "1010110": "3",
    "1011100": " ",
    "0011101": ":",
    "0011011": "!",
    "0110101": "&",
    "1101001": "#",
    "1100101": ")",
    "1001101": "8",
    "0010111": "`",
    "0011110": "(",
    "0111001": ".",
    "1011001": ",",
    "0101101": "0",
    "0101110": '1',
    "1010101": "4",
    "1001011": "'",
    "1110100": "5",
    "1001110": "7",
    "0111100": ";",
    "0100111": "2",
    "0111010": "/",
    "0101011": "6",
    "1100011": "\"",
    "1111000": "",
    "0110110": "FIGS",
    "1011010": "LTRS",
}

mode=figures # variable to switch between letters and figures alphabets

input="101101001101101101001110100110110101110100110100101101101010110101110010110100101110100111001101100101101101101000111100011110011011010101011001011101101010010111011100100011110101010110110101011010111001011010110100101101101010110101101011001011010011101110001101100101110101101010110011011100001101101101101010101101101000111010110110010111010110101100101100110111101000101011101110001101101101001010111001011101110001010111001011100011011"

for w in range(0, len(input), 7):  # generate sequence 0, 7, 14 ... 441
    word = input[w:w+7] # take 7 characters starting at i
    if mode[word] == "FIGS":
        mode = figures
    elif mode[word] == "LTRS":
        mode = letters
    else:
        print(mode[input[w:w+7]], end="")  # print letter from alphabet that corresponds to the sequence