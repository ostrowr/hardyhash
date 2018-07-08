#include <sys/stat.h>

#include <string>

#include "initialize.hh"
#include "sign.hh"
#include "verify.hh"


using std::cout;
using std::cerr;
using std::endl;
using std::string;

void do_sign(int argc, char *argv[]) {
    cout << "signing..." << endl;
}

void do_verify(int argc, char *argv[]) {
    cout << "verifying..." << endl;
}

void do_initialize(int argc, char *argv[]) {
    if (argc != 6) {
        cout << endl
             << "Usage:" << endl
             << "\t./hardyhash initialize <lg_n_signers> <lg_messages_per_signer> <randomness> <output_dir>" << endl
             << endl
             << "\tlg_n_signers must be an even integer between 2 and 16, inclusive." << endl
             << "\tlg_messages_per_signer must be an even integer between 2 and 16, inclusive." << endl
             << "\trandomness should be a source of entropy, at most 1024 characters long." << endl
             << "\toutput_dir must be a path to the desired output directory, which must not exist." << endl
             << endl;
             exit(1);
    }
    size_t lg_n_signers = std::stoi(argv[2]);
    size_t lg_messages_per_signer = std::stoi(argv[3]);
    string randomness = argv[4];
    string out_dir = argv[5];

    if (lg_n_signers % 2 || lg_n_signers > 16 || lg_n_signers < 2) {
        cerr << endl
             << "ERROR: lg_n_signers must be an even integer between 2 and 16, inclusive." << endl
             << endl;
             exit(1);
    }

    if (lg_messages_per_signer % 2 || lg_messages_per_signer > 16 || lg_messages_per_signer < 2) {
        cerr << endl
             << "ERROR: lg_messages_per_signer must be an even integer between 2 and 16, inclusive." << endl
             << endl;
             exit(1);
    }

    struct stat buf;
    if (stat(out_dir.c_str(), &buf) == 0) {
        cerr << endl
             << "ERROR: output directory already exitsts."
             << endl;
        exit(1);
    }

    int status = mkdir(out_dir.c_str(), S_IRUSR | S_IWUSR | S_IXUSR);
    if (status) {
        cerr << endl
             << "ERROR: output directory could not be created."
             << endl;
        exit(1);
    }

    cout << "Initializing..." << endl;
    keys_t *k = initialize(lg_n_signers, lg_messages_per_signer,
                           reinterpret_cast<const byte *>(randomness.c_str()),
                           randomness.length());
    cout << "Writing signer states and public key to "
         << out_dir << " ..." << endl;
    write_signer_states(k, out_dir);
    cout << "Initialized successfully." << endl;
    delete k;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        cout << endl << "Usage: hardyhash COMMAND" << endl;
        cout << endl;
        cout << "Commands:" << endl;
        cout << "  initialize" << endl;
        cout << "  sign" << endl;
        cout << "  verify" << endl;
        cout << endl;
        cout << "Run `hardyhash COMMAND` with no arguments for more information about the command."
             << endl
             << endl;
        exit(1);
    }
    string command = argv[1];
    if (command == "initialize") {
        do_initialize(argc, argv);
    } else if (command == "sign") {
        do_sign(argc, argv);
    } else if (command == "verify") {
        do_verify(argc, argv);
    } else {
        cout << "Command must be one of 'initialize', 'sign', or 'verify'." << endl;
        exit(1);
    }
    return 0;
}
