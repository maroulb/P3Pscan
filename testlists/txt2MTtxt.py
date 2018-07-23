import sys

txt = sys.argv[1]

name, fxt = txt.split('.')

liste = open(txt, 'r')
num_lines = sum(1 for line in liste)
print num_lines
liste.close()

rankingListe = open(name+'MT.txt', 'w')
liste = open(txt, 'r')

for i in range(num_lines):
    url = (liste.readline().rstrip('\n'))
    rankingListe.write(str(i+1) + ',' + url + '\n')

liste.close()
rankingListe.close()
