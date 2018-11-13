
use std::u16;
use std::ptr;
use std::num::*;
use std::ops::*;

use ::reduce::barrett_reduce;
use ::params::{Q, N};


pub fn coeff_freeze(x: u16) -> u16 {
    let mut r = barrett_reduce(x);
    let m = r.checked_sub(Q as u16).unwrap_or(u16::MAX - Q as u16);
    let mut c = m as i16;
    c >>= 15;
    r = m ^ ((r ^ m) & c as u16);
    r
}

fn flip_abs(x: u16) -> u16 {
    let mut r = coeff_freeze(x) as i16;
    r = r - Q as i16/2;
    let m = r >> 15;
    ((r + m) ^ m) as u16
}

fn byte_of_u32(v: u32) -> u8 {
    unsafe {
        std::mem::transmute::<u32, [u8; 4]>(v.to_le())[0]
    }
}

fn byte_of_u16(v: u16) -> u8 {
    unsafe {
        std::mem::transmute::<u16, [u8; 2]>(v.to_le())[0]
    }
}

pub fn memwipe(val: &mut [u8]) {
    let zeros = vec![0u8; val.len()];
    unsafe {
        ptr::copy_nonoverlapping(&zeros[0] as *const u8, &mut val[0] as *mut u8, val.len());
    }
}

pub fn compress(r: &mut [u8], p: &[u16; N]) {
    let mut t = [0u32; 8];

    let mut i = 0;
    let mut k = 0;
    while i < N {
        for j in 0..t.len() {
            t[j] = coeff_freeze(p[i+j]) as u32;
            t[j] = (((t[j] << 3) + Q as u32/2) / Q as u32) & 0x7;
        }

        r[k] = byte_of_u32(t[0]) | byte_of_u32(t[1]<<3) | byte_of_u32(t[2]<<6);
        r[k+1] = byte_of_u32(t[2]>>2) | byte_of_u32(t[3]<<1) | byte_of_u32(t[4]<<4) | byte_of_u32(t[5]<<7);
        r[k+2] = byte_of_u32(t[5]>>1) | byte_of_u32(t[6]<<2) | byte_of_u32(t[7]<<5);
        i += 8;
        k += 3;
    }

    for i in 0..t.len() {
        t[i] = 0;
    }
}

pub fn decompress(a: &[u8], p: &mut [u16; N]) -> Vec<u8> {
    let mut ma_a: Vec<u8> = vec![0u8; a.len()];
    ma_a.copy_from_slice(a);
    for i in (0..N).step_by(8) {
        let (a0, a1, a2) = (ma_a[0] as u16, ma_a[1] as u16, ma_a[2] as u16);
        p[i+0] = a0 & 7;
        p[i+1] = (a0 >> 3) & 7;
        p[i+2] = (a0 >> 6) | ((a1 << 2) & 4);
        p[i+3] = (a1 >> 1) & 7;
        p[i+4] = (a1 >> 4) & 7;
        p[i+5] = (a1 >> 7) | ((a2 << 1) & 6);
        p[i+6] = (a2 >> 2) & 7;
        p[i+7] = a2 >> 5;
        let mut new_a = vec![0u8; ma_a[3..].len()];
        new_a.copy_from_slice(&ma_a[3..]);
        ma_a = new_a;
        for j in 0..8 {
            p[i+j] = ((p[i+j] as u32 * Q as u32 + 4) >> 3) as u16;
        }
    }
    ma_a
}

fn from_msg(msg: &[u8], p: &mut [u16; N]) {
    for i in 0..32 {
        for j in 0..8 {
            let mask = 0-((msg[i] >> j) & 1);
            p[8*i+j+0] = mask as u16 & (Q as u16/ 2);
            p[8*i+j+256] = mask as u16 & (Q as u16/ 2);
            p[8*i+j+512] = mask as u16 & (Q as u16/ 2);
            p[8*i+j+768] = mask as u16 & (Q as u16/ 2);
        }
    }
}

pub fn to_msg(msg: &mut [u8], p: &[u16; N]) {
    memwipe(&mut msg[0..32]);

    for i in 0..256 {
        let mut t = flip_abs(p[i+0]);
        t += flip_abs(p[i+256]);
        t += flip_abs(p[i+512]);
        t += flip_abs(p[i+768]);
        t = t.checked_sub(Q as u16).unwrap_or(u16::MAX - 1);
        t >>= 15;
        msg[i>>3] |= byte_of_u16(t << (i & 7));
    }
}

pub fn sub(p: &mut [u16; N], a: &[u16; N], b: &[u16; N]) {
    for i in 0..N {
        p[i] = barrett_reduce(a[i] + 3*Q as u16 - b[i]);
    }
}


#[cfg(test)]
mod tests {
    extern crate rustc_serialize;
    extern crate rand;
    extern crate byteorder;

    use byteorder::{ByteOrder, LittleEndian};
    use self::rustc_serialize::hex::{ToHex, FromHex};
    //use self::rand;
    use self::rand::Rng;
    use self::rand::os::OsRng;
    use super::super::params::N;
    use super::{coeff_freeze, compress, flip_abs, decompress};

    #[test]
    fn coeff_freeze_test() {
        let x = 12345;
        let y = coeff_freeze(x);
        assert_eq!(y, 56);
    }

    #[test]
    fn flip_abs_test() {
        let x = 12345;
        let y = flip_abs(x);
        assert_eq!(y, 6088);
    }

    fn set_u16_le(a: &mut [u8], v: u16) {
        a[0] = v as u8;
        a[1] = (v >> 8) as u8;
    }

    #[test]
    fn compress_test() {
        let input = String::from("125867141b17a6654f3eaa18b38d164c8bdf5325fbe2aac66e1100f718aa3d2452f944689166d692d36b20cee71f795bd1626d3ead811445fc08d16d362ae1fc96060f443b6bfe24784c1032caa4f9e7a6637ef801acd8654ad9cd6cdc05efd0af7c4a75c955e0dcba38f4a6827a84814f858cf9a1ca325866271d60702ec5167acdbcf3715f5573a7b5f2ebdd7a83d809649370c5ee324a707fd9a0d14b527c115b89f72758f627140f11e118c55f854e8ab57b7f7be4c617666cc3695c66299aac72bb822d36a83d571b19aaafc8dc3c964b5ff219e253df6efc9dd567b5b77b72c6f1ca44e11fbdf83c34de5089a6b2a52e6f620db074a23cd94bbf3d8f3e410c392eeee4fc21a12930de529346bfebe34ca3e8e10f380de42d39a750b8a6a8443d2b47771361f0855d308466fc6dc3ba5c7aca382670370d63946c3c0b917671da7b6ca17dbd11279446899bd90105c50aafd7972e804a30ea01ab2120d48248764ab0277e460425b21ca5e72520e8bc1e516c88aa9b0383315f628c5a4f81a6b9e8432b23aca4c0899212386390ff6df778e29971a9a633c2f704e17d418c926fd588e45683becc70ee143fa21f714c438c8663a34461848c56aace58386521425f99bf1c65f66a2e8136bee0cc2de24ea109ec02c08fd73230e2f2e489100ec990986e5cfa3588cae04efed29caad87521c395dc258d4f0215459b2b2e27d2092c36f8fa3d521f6084c8660db7867c7f507e9945d309c70373669858da519f37b6d43e91694452cdd973148744a3f39c5000fe28287ff3b6bd14feba585ca5aa4642ec92d8ab0279963ee367bc3025b2271495bfde6b114acfb32a9845811fb3733658303eba1fc4df303b479b72263fd336b07ffd93f518321e43628026cc4f8c0181d778e1069992e838c8ec4c787ac08b9309299c961c650ef7f3adf39848d28c610ed9a50bae3ed2609425b00f3103095a75933f8e685e91a86328d70c82bc22917fb69b1d9487e11ae453196ef3ad1b2b7fff778ba9daf31d8cbd01f9e312745455420b9e87488dc6eacc6969a79f49798c53d2a18a272cffdcf509b563c8aae852c5994297971c1cb087231e89cfb8ac1371f5247b40bc60e150347ac05923648261d937d82f21f4dc3069f2a616f5f45bf8f5531aa490a14a5833dc4b2f19f3c3d755ecb57c93aa613b737876a48903b44663c1e844b38a92d3910d8b4eb70fb24465de12489f5784a1f959d0205defd3a9ffb9f58664d3b1c03be6de8c7b587cb6a0b164a6205ddd9cc9cdb6c2623f65de146dacc69b53b3f0f9da9a6fe94a4b1a5f91df7b8965a287524e06e8bedd8af6140ffaaa42eded5f677bb651ecc8758985f9e5d4309a920d8e5494b74104914d3b5f1a657401d320a67e2d9480365814ea7aaf5234c5520881e89ec68d74640eec3ff0c63803e13080f76bd3c702c8fe8b597274129a7b7acef77e0ffc5bd5a78f8667108080eb384ca6ab4299cb10f0794c73763ab0ae35c7305c8deae7e3cfff852b3f58f56ee5a6df6213f18e07851018ef1b3c909367fec08600eae9ccc9c1676f8127dea19a19b065c027ee7de4f32b8fad889f5a3ec666071efa6ce470400d6ff0f4f3d864e9b5abc669b206992528c87294cd79a1282e2a8f3236ce7fd165ddb4bacbd8c96bb73bded5d19ad92d9641daffee467a1bbb5f1e3f6e52dce2b04fbb723cac2959067e8ab6bff038ad681318c15646a9c2d3f5c16ad489a8eee96384c614932740761b167a36e29f16eba1e140c4e8852724d93af405b9e88667c89a266721d970bda63ac990d7530afc17f3c493d4306895c7d1acb6bf1db75e5e60ab698ace1272f5edd93b13e133822458f8b864297e8423c4521a1ebaee84b04bcab62b299ed628bc11325141aff30aa6c137d309edcb0df752ee26f2eb579c08756b1dff7508ffffa7fde0c58e03304026b937458bc86e979c3f8c75d76d5fff1d94dd7bcfe12caf2a528211f2c8294e97e5acf8f86f125fee062b4c9355bcf035145700f419590d137f5fa949af84d021e6fbc2263e879a6226d3fc02f50b7b0c54b253c77c4805f1ce383422cc0c281473ffba0c276596e2046de45fb4a2eed77e8a086e34a37629b197b6263c30a0fcf7fe14b9ebea117d9e3b83eca229949df767e064f8068af9dba66878619c6b5126402184b9a6172d03cbd7fcc23adedae3622862b39f9738fc67c8b24fa002bd7b7eb9b399646a5b7ae816acdc6729eec21021b02648b5d3587feacc84b1b329518db6f5207efcdd42295e08bdde472ca03294e95511906a7b9daf1aef8153a0243cc4d58a44a59d954df70d3c897bda192b9ce7265c69081e662a5703d7dac48e683058bca059a682bbd43bbaea23ac59c0f89d54a66d05b748b1b8a31ab5df1233e6fe776c281594664e45d030f98c0ae61cce1f349aab16e1ef80b4448a93d25f6cb32b828876f998023a06ecf196b4cc68c1c0ae815d6e680276f1e8a6005c28cfafc1b838de9e0613252ead8dec99da103130962beb2b7cccfd087d33a8ed6e11a49f54fc6e4aa3bdb1bc3f907ca928e439062c87fbd7b79411454506a83156f6458064d86e9a95796651a7176ebb74d67f6e46b4996c0cd8187ecf12ca0db8cdeedb58b2467b0be0d277ce216fccb89098a7bf47d02c54658f33a39b606c9252ab65acb4da6fd7d0a7d02122b3bb8adc993b1e0f6bd9e06ffab1e273a141d8e10df846b3e89a5c08e12023b0e5e263fef69e33e3de9f0a66f8be33a0f9c1897bb9e592b7917951e245d3a307bd2ea6818d6adc866368ce255653ad0c84a713f7c978e175260bc5d4dcad9f0b149a5de8d8664c4b3bf8886207b454253b4b73b25acdd2fb00dffa4aef9e2bf2111d6bfc");
        let expected = String::from("1f23a2b5b3d04a20f590195d995cec494365a51bd2967e800ae69319d8b5cf3fc76f93fc3d78b6012de5c39a949ca64a82fd069e63953b614467a608eb700a690a78e4e9bef765bcfc0b04a29874a02dac7d662b062243de41e082f44a745c0a7b54e7ad9685b3646ea91ee8e489f87eba9dddd54a5e15ac7a19e4449ea41928c1cb03f03adcd3ea77169927461abd2fceb3f45de7a17c100460e2ed45f8525c887dea567e2f780ffe6d42c2aa181c89e67d330275ae497e8aa04d4627cfb40419f489d9e9359c5036c0e7c51dcc22c0155705fc4ea926248ef569401a4bef1882afdaeb39129ac378ef6476c7561e8510ac04990b4883ecff0eeffa3c16460af06899929dc9a8a5ae973a436a0c54d9199295da8da2ef4f6c34a1ad659fbca47903d96788fa8e52f412d9c3f66fdbd5002e460b3b67a252561f02bf773fd63dcf7c3aa915e14fbf1038b0007e880668f895601371d039c320a5689eb2d849754b0be413c9f136bf1ae7cdb1d25af282a13ebdc0726c31a456e96960d75229540000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        let input_bytes = input.from_hex().unwrap();
        let expected_bytes = expected.from_hex().unwrap();

        let mut r = vec![0u8; 500];
        let mut p = vec![];

        for i in (0..input_bytes.len()).step_by(2) {
            let x = LittleEndian::read_u16(&input_bytes[i..]);
            p.push(x);
        }
        let mut p_array = [0u16; 1024];
        p_array.copy_from_slice(&p);
        compress(&mut r, &p_array);
        //println!("ar {}\n", r.to_hex());
        assert_eq!(r, expected_bytes);

        //let mut new_poly = [0u16; N];
        //decompress(&r, &mut new_poly);
        //assert_eq!(&p_array[..], &new_poly[..]);
    }
}
