in1 = "aaaabbbbccccdddd"
out1 = "ccaccdabdbdbbada"
in2 = "abcdabcdabcdabcd"
out2 = "bcaadbdcdbcdacab"
resolved_positions = [-1] * 16
for i in range(16): # iterate over each position 0..15 and analyze what a resulting possible positions (aka candidates)
    candidates = []
    for j in range(16):
        # if input character at position i is same as output character at position j for both lines
        # then this position j is one of candidate shuffles
        if out1[j] == in1[i] and out2[j] == in2[i]:
            candidates.append(j)
    print(i, candidates)
    if len(candidates) == 1: # if number of candidates is 1, then we uniquely identifies transformation and can store it
        resolved_positions[i] = candidates[0]

print(resolved_positions)
challenge = "owuwspdgrtejiiud"
for i in range(16):
    print(challenge[resolved_positions[i]], end="")
