"""
 Put Binary into list then split list in half and return both halves
 @:param int plaintext                      binary value
 @:param int bitSize                        size of binary array
 @:return int[] leftSide, int[] rightSide   two halves of plaintext binary value as int arrays
"""
def splitBinaryToLeftAndRight(plaintext, bitSize):
    binaryList = [0] * bitSize
    temp = plaintext
    for i in range(0, bitSize):
        binaryList[(bitSize - 1) - i] = temp % 2
        temp //= 2

    splitIndex = int(bitSize / 2)
    leftSide = binaryList[:splitIndex]
    rightSide = binaryList[splitIndex:]

    return leftSide, rightSide


"""
 Expand 4 bit binary array to a 6 bit binary array
 @:param int[]  fourBitArray            4 bit binary array to expand
 @:return int[] expandedfourBitArray    expanded 6 bit binary array
"""
def expansionBox(fourBitArray):
    fourBitArrayTail = fourBitArray[-1]
    fourBitArrayHead = fourBitArray[0]

    expandedfourBitArray = fourBitArray
    expandedfourBitArray.insert(0, fourBitArrayTail)  # Put tail element at head
    expandedfourBitArray.insert(5, fourBitArrayHead)  # Increase index and put head element at new tail

    return expandedfourBitArray

"""
Split cipher key, apply left shift to each split array, then add permutation to new cipherkey array
@:param int[]  cipherKey
@:return int[] roundKey
"""
def defineRoundKey(cipherKey):
    keyPermutation = [5, 6, 1, 4, 2, 3]

    leftSide, rightSide = splitBinaryToLeftAndRight(cipherKey, 6)
    rightSide.insert(3, rightSide.pop(0))   # Left Shift Right Side
    leftSide.insert(3, leftSide.pop(0))     # Left Shift Left Side

    combinedKey = leftSide + rightSide


    permutedKey = [0] * 6
    for i in range(0, 6):
        permutedKey[keyPermutation[i] - 1] = combinedKey[i]
    return permutedKey   # Round Key

"""
Return value of SBox from calculated row and column from xored array
@:param int[] xoredValue    array of binary from xored arrays
@:return int[] SBox          array of binary from calculated SBox value
"""
def SBoxSubstitution(xoredValue):
    SBox1 = [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ]

    # Store proper bits to proper SBox array
    rowBits = [xoredValue[0], xoredValue[-1]]
    columnByte = xoredValue[1:5]

    # Convert binary arrays to int values
    rowInt = 0
    for bit in rowBits:
        rowInt = rowInt << 1 | bit

    colInt = 0
    for bit in columnByte:
        colInt = colInt << 1 | bit

    SBoxValue = SBox1[rowInt][colInt]
    SBoxArray = [0] * 4
    index = 0
    # Convert int to Binary Array
    while SBoxValue > 0:
        remainder = SBoxValue % 2
        SBoxArray[index] = remainder
        SBoxValue //= 2
        index += 1

    SBoxArray.reverse()     # Reverse Order for correct orientation

    return SBoxArray

"""
Apply straight permutation to an array
@:param int[] SBox      array of resulting SBox value in Binary
@:return int[] PBox      array of resulting PBox value in Binary
"""
def PBoxPermutation(SBox):
    straightPermutation = [3, 4, 1, 2]
    PBox = [0] * 4
    for i in range(0, 4):
        PBox[straightPermutation[i] - 1] = SBox[i]

    return PBox
"""
@:param int[] array1        first array to XOR
@:param int[] array2        second array to XOR
@:return int[] resultArray   XOR result of array1 and array2
"""
def xorTwoArrays(array1, array2, bitSize):
    resultArray = [0] * bitSize
    for xorIndex in range(0, bitSize):
        resultArray[xorIndex] = array1[xorIndex] ^ array2[xorIndex]

    return resultArray

"""
Convert binary array into an integer value
@:param int[] binArray      Binary array to convert to integer
"""
def convertBinArrayToInt(binArray):
    result = 0
    binArray.reverse()
    for bitIndex in range(0, 8):
        result += binArray[bitIndex] * (2 ** bitIndex)

    return result

"""
Apply encryption algorithm
@:param int plaintext               int value of plaintext data
@:param int cipherkey               int value of cipherkey data
@:return int finalEncryption        int value of encrypted data
"""
def encrypt(plaintext, cipherkey):

    leftSide, rightSide = splitBinaryToLeftAndRight(plaintext, 8)

    # Copy Right Side into Left Side to protect for final encryption
    finalLeftSide = rightSide[:]

    expandedRight = expansionBox(rightSide)

    roundKey = defineRoundKey(cipherkey)

    # XOR expansion permutation and round key
    xorArray = xorTwoArrays(expandedRight, roundKey, 6)

    SBoxArray = SBoxSubstitution(xorArray)

    PBox = PBoxPermutation(SBoxArray)

    # XOR original left side with PBox Permutation
    finalRightSide = xorTwoArrays(PBox, leftSide, 4)

    finalEncryption = finalLeftSide + finalRightSide

    return convertBinArrayToInt(finalEncryption)

"""
 Decrpytion Algorithm 
 @:param int ciphertext            int value of ciphertext data
 @:param int cipherkey             int value of cipherkey data
 @return int decryptedData       int value of decrypted data
"""
def decrypt(ciphertext, cipherkey):
    leftSide, rightSide = splitBinaryToLeftAndRight(ciphertext, 8)
    # Swap Sides
    newLeft = rightSide[:]
    newRight = leftSide[:]

    finalLeft = newRight[:]

    expandedRight = expansionBox(newRight)

    roundKey = defineRoundKey(cipherkey)

    xoredArray = xorTwoArrays(expandedRight, roundKey, 6)

    SBox = SBoxSubstitution(xoredArray)

    PBox = PBoxPermutation(SBox)

    finalRight = xorTwoArrays(PBox, newLeft, 4)
    finalDecryption = finalRight + finalLeft

    return convertBinArrayToInt(finalDecryption)


def main():
    plaintext = 0b10111111
    cipherkey = 0b101011
    print("Problem 1:")
    print("Original Plaintext:", hex(plaintext))

    encryptedCipher = encrypt(plaintext, cipherkey)
    print("Encrypted Cipher:", hex(encryptedCipher))

    decryptedCipher = decrypt(encryptedCipher, cipherkey)
    print("Decrypted Cipher:", hex(decryptedCipher))

    # Problem 2
    print("\nProblem 2:")
    threeDESEncryption = encrypt(encrypt(encrypt(plaintext, cipherkey), cipherkey), cipherkey)
    threeDESDecryption = decrypt(decrypt(decrypt(threeDESEncryption, cipherkey), cipherkey), cipherkey)
    print("Original Plaintext:", hex(plaintext))
    print("3DES Encryption:", hex(threeDESEncryption))
    print("3DES Decryption:", hex(threeDESDecryption))


if __name__ == "__main__":
    main()
