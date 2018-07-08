rm -rf out
./hardyhash initialize 8 8 randomness out

for ((i=0; i<257; i++)); do
    dd if=/dev/urandom of=tmp.random bs=100000 count=1 >& /dev/null;
    ./hardyhash sign out/signer_0 tmp.random outfile;
    ./hardyhash verify out/public_key tmp.random outfile;
    rm outfile
done

rm tmp.random;