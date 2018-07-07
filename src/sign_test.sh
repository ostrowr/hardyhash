./initialize 8 8 randomness out

for ((i=0; i<257; i++)); do
    dd if=/dev/urandom of=tmp.random bs=100000 count=1 >& /dev/null;
    ./sign out/signer_1 tmp.random outfile;
    ./verify out/public_key tmp.random outfile;
done

rm tmp.random;