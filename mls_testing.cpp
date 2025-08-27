// mls_testing.cpp
// toy demo for using the mlspp library.

#include <iostream>
#include <stdexcept>

#include <chrono>
#include <thread>

#include <mls/credential.h>
#include <mls/crypto.h>
#include <mls/session.h>
#include <mls/messages.h>

using namespace MLS_NAMESPACE;

const CipherSuite SUITE { CipherSuite::ID::X25519_AES128GCM_SHA256_Ed25519 };

int main() {

    /*
        To keep track of the narrative, we'll have 3 members: Raven, Hawk, and Goose.
        First: Raven and Hawk start up - with Raven starting the group. 
    */

    // Raven: Originator behavior.
    mls::Client Raven_Client = mls::Client(
        SUITE,
        mls::SignaturePrivateKey::generate(SUITE),
        mls::Credential::basic(
            from_ascii("RAVEN")
        )
    );
    std::cout << "--- Raven established client." << std::endl;
    mls::Session Raven_Session = Raven_Client.begin_session(from_ascii("BirdBath"));
    std::cout << "  - Raven began a session." << std::endl;
    std::cout << std::endl;





    // Hawk: Non-originator behavior.
    mls::Client Hawk_Client = mls::Client(
        SUITE,
        mls::SignaturePrivateKey::generate(SUITE),
        mls::Credential::basic(
            from_ascii("HAWK")
        )
    );
    std::cout << "--- Hawk established client." << std::endl;
    mls::PendingJoin Hawk_Join = Hawk_Client.start_join();
    auto kp_Hawk = Hawk_Join.key_package();
    std::cout <<  "  - Hawk generated a keypackage." << std::endl;

    std::cout << std::endl;
    
    /*
        Next, Raven adds Hawk based on their generated keypackage.
        - adding the keypackage generates a proposal
        - commiting the proposal generates both the commit and welcome messages
        - handling the commit rolls the epoch over for existing members
        - completing on the welcome initializes the session for the newcomer. 
    */
   
    // Originator adds on keypackage.
    auto add_Hawk = Raven_Session.add(kp_Hawk);                           // This generates a "proposal" that everyone needs to handle
    Raven_Session.handle(add_Hawk);                                       // Everyone handles the proposal
    auto [welcome_add_Hawk,commit_add_Hawk] = Raven_Session.commit();       // This generates the welcome and commit messages
    Raven_Session.handle(commit_add_Hawk);                                  // Everyone handles the commit
    std::cout << "--- Raven adds Hawk to the session." << std::endl;    

    // Recipient of welcome joins the session
    mls::Session Hawk_Session = Hawk_Join.complete(welcome_add_Hawk);       // Hawk joins on welcome message  
    std::cout << "  - Hawk joins." << std::endl;

    /*
        We'll demonstrate message passing. Keep track of the naming convention, as we'll see in the
        next section how epoch updates provide forward secrecy so you can't get access to the old 
        epoch's messages. 
    */ 
    bytes epoch_1_msg_Raven = Raven_Session.protect(from_ascii("Nevermore, as quoted in epoch 1"));
    try{
        auto epoch_11_msg_Hawk = to_ascii(Hawk_Session.unprotect(epoch_1_msg_Raven));
        std::cout << "  - Hawk able to decode epoch 1 message: " << epoch_11_msg_Hawk << std::endl;
    }catch(...){
        std::cout << "  - Hawk unable to decode epoch 1 message" << std::endl;
    }
 
    std::cout << std::endl;

    // Third member starts up
    mls::Client Goose_Client = mls::Client(
        SUITE,
        mls::SignaturePrivateKey::generate(SUITE),
        mls::Credential::basic(
            from_ascii("GOOSE")
        )
    );
    std::cout << "--- Goose established client." << std::endl;
    mls::PendingJoin Goose_Join = Goose_Client.start_join(); // Demonstrate an external join?
    auto kp_Goose = Goose_Join.key_package();
    std::cout << "  - Goose generated a keypackage." << std::endl;
 
    std::cout << std::endl;
    
    /*
        Originator adds on keypackage (it does not actually matter who adds this person, but keeping
        it consistent that the originator takes responsibility for adds keeps the example simple.)
    */
    auto add_Goose = Raven_Session.add(kp_Goose);                           // Generates proposal
    Raven_Session.handle(add_Goose);                                        // Everyone handles proposal
    Hawk_Session.handle(add_Goose);
    auto [welcome_add_Goose, commit_add_Goose] = Raven_Session.commit();    // Generates welcome and commit
    Raven_Session.handle(commit_add_Goose);                                 // Everyone handles commit
    Hawk_Session.handle(commit_add_Goose);
    std::cout << "--- Raven adds Goose to the session." << std::endl;

    // Recipient of welcome joins session
    mls:Session Goose_Session = Goose_Join.complete(welcome_add_Goose);
    std::cout << "  - Goose joins." << std::endl;                                  

    /*
        Another round of message passing. We see forward secrecy, in this new epoch, the prior messages
        can no longer be decoded. 
    */
    bytes epoch_2_msg_Raven = Raven_Session.protect(from_ascii("Deep into that darkness peering, in epoch 2"));
    try {
        auto epoch_12_msg_Goose = to_ascii(Goose_Session.unprotect(epoch_1_msg_Raven)); 
        std::cout << "  - Hawk / Goose able to decode epoch 1 message: " << epoch_12_msg_Goose << std::endl;
    }catch(...){
        std::cout << "  - Hawk / Goose unable to decode epoch 1 message" << std::endl;
    }
    try {
        auto epoch_22_msg_Goose = to_ascii(Goose_Session.unprotect(epoch_2_msg_Raven));
        std::cout << "  - Hawk / Goose able to decode epoch 2 message: " << epoch_22_msg_Goose << std::endl;
    }catch(...){
        std::cout << "  - Hawk / Goose unable to decode epoch 2 message" << std::endl;
    }

    std::cout << std::endl;



    /*
        Now, Hawk will push an update.
        Upsettingly, the Update process is just running an empty commit. Seems like the sesion.update
        method does not actually do what we hoped it would do. 
    */
    auto [welcome_update_Hawk, commit_update_Hawk] = Hawk_Session.commit();     // generate commit
    silence_unused(welcome_update_Hawk);                                        // dispose of unused welcome
    Raven_Session.handle(commit_update_Hawk);                                  // everyone handles commit
    Hawk_Session.handle(commit_update_Hawk);
    Goose_Session.handle(commit_update_Hawk);
    std::cout << "--- Hawk prompts and update; everyone handles the commit." << std::endl;
    
    bytes epoch_3_msg_Raven = Raven_Session.protect(from_ascii("Caw, in epoch 3"));
    try {
        auto epoch_13_msg_Goose = to_ascii(Goose_Session.unprotect(epoch_1_msg_Raven)); 
        std::cout << "  - Hawk / Goose able to decode epoch 1 message: " << epoch_13_msg_Goose << std::endl;
    }catch(...){
        std::cout << "  - Hawk / Goose unable to decode epoch 1 message" << std::endl;
    }
    try {
        auto epoch_23_msg_Goose = to_ascii(Goose_Session.unprotect(epoch_2_msg_Raven));
        std::cout << "  - Hawk / Goose able to decode epoch 2 message: " << epoch_23_msg_Goose << std::endl;
    }catch(...){
        std::cout << "  - Hawk / Goose unable to decode epoch 2 message" << std::endl;
    }
    try {
        auto epoch_33_msg_Goose = to_ascii(Goose_Session.unprotect(epoch_3_msg_Raven));
        std::cout << "  - Hawk / Goose able to decode epoch 3 message: " << epoch_33_msg_Goose << std::endl;
    }catch(...){
        std::cout << "  - Hawk / Goose unable to decode epoch 3 message" << std::endl;
    }

    std::cout << std::endl;

    std::cout << std::endl;

    

    return 0;
}

// A. J. Beal