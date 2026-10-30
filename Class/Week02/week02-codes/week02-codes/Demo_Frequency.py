from collections import Counter

text = """
Yic blcw uf, wlc cxlbw blk twk ckfb cxflo twlj uk Twlo Pilxki 1 bkcx ukfb eij pl cxkqic cwlc ulc uic blk twk Twlo Plc ot bf bf wfo two ulk, ulc uic xolj bwlt pkfcx. Xolo ZUAX Twlo Plc akq uocw jfo ufo ukfb ulcx nq 7 blk twk ckfb cxflo zl nwfcx xofo wlc blk twk Ufcx Clj L. Tfo ul 5 blk twk ckfb cxflo zl 2 Ufcx Clj L ukfb two ulk bkcx pkb tric glc. F yfcx ul ck, Twlo Plc twkl Mwopommocig glk pflt pklc pkk f ylc nit, rfo twlcx Ocufcigol ui xolcw WB ufcx. Jlulj Mlcx twkl cwlc bwlj trlc Mwopommocig xof rlt nwf nwlc, zo 18 trfcx 23 blk twk ufo mwkfcx jlcx ufcx jlk plo. Tkq cwoic, yl bkcx twkl cwlc yfcx ul ck Twlo Plc ulcx bwkqic ufo bwlj bwlm. Tfo mwlo twkl cwlc rlcx trfcx 8 clj akl, ni tk nwo tfo nwfcx bfc trkb toim aklc pq ufo tkqic ck, bwkcx tl zlc ulcx ukcx cwoik blk twk bk, yl Mlcx bwf yoit. Blb blk twk jlcx ufcx jlk plo, wflb two ulk f ckfb cxflo bwkl bf cwoik twfo xolc tlm pkqic zl bwkl wfl cwlm ukfb.
"""

# Count character frequency
freq = Counter(text)

# Print in descending order
for char, count in freq.most_common():
    # Skip spaces and newlines
    if char.strip():
        print(f"{char} : {count}")