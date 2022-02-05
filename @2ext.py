import os

SOURCE = "./"

file_list = os.listdir(SOURCE)
file_list_csv = [file for file in file_list if file.endswith(".scb")]

index = 0
os.mkdir(SOURCE+"bnsf/")
for file in file_list_csv:
    bnsfindex = []

    with open(SOURCE+file, "rb") as f:
        f.read(8)
        length = int.from_bytes(f.read(4), byteorder='big')
        f.read(116)
        fullfile = bytearray(f.read(length))
        print(length)
    bnfs = fullfile.split(b'\x42\x4E\x53\x46')

    for idx, sound in enumerate(bnfs):
        if idx == 0 :
            continue
        diff = 0
        paddingcnt=0
        lastbytes = sound[-16:]
        for byte in lastbytes:
            if byte == 0:
                paddingcnt += 1

        if paddingcnt != 0 :
            for cnt in range(0, paddingcnt):
                sound.pop(len(sound)-1)

        if len(sound) != int.from_bytes(sound[:4], byteorder='big')+4:
            diff = int.from_bytes(sound[:4], byteorder='big')+4 - len(sound)

        for i in range(0,diff):
            sound.append(0)

        filepath = file[:-7] + format(idx, '03') + ".bnsf"
        with open(SOURCE+"bnsf/" + filepath, "wb") as f:
            f.write(b'\x42\x4E\x53\x46')
            f.write(sound)

    