
extern crate rand;
extern crate newhope;

use self::rand::Rng;
use self::rand::os::OsRng;

use newhope::simple::{generate_keypair_simple_alice, key_exchange_simple_bob,
                   key_exchange_simple_alice};


//#[test]
fn test_simple_integration() {
    let mut rng = OsRng::new().unwrap();
    for i in 0..1024-1 {
        let (alice_priv, alice_pub) = generate_keypair_simple_alice(&mut rng);
        let (mut bob_pub, bob_shared) = key_exchange_simple_bob(&mut rng, &alice_pub);
        let alice_shared = key_exchange_simple_alice(&mut bob_pub, &alice_priv);

        assert_eq!(alice_shared, bob_shared);
    }
}
