// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "zoobc/crypto/slip10.h"
#include <sodium.h>
#include <openssl/evp.h>
#include <regex>
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <cstring>
#include <cctype>

namespace zoobc {
namespace crypto {

namespace {

// HMAC-SHA512 helper
std::array<uint8_t, 64> HMAC_SHA512(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data) {
    std::array<uint8_t, 64> output;
    crypto_auth_hmacsha512_state state;

    crypto_auth_hmacsha512_init(&state, key.data(), key.size());
    crypto_auth_hmacsha512_update(&state, data.data(), data.size());
    crypto_auth_hmacsha512_final(&state, output.data());

    return output;
}

// Base32 alphabet (RFC 4648)
const char* BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// Base32 encoding
std::string Base32Encode(const std::vector<uint8_t>& data) {
    std::string result;
    result.reserve((data.size() * 8 + 4) / 5);

    uint32_t buffer = 0;
    int bits = 0;

    for (uint8_t byte : data) {
        buffer = (buffer << 8) | byte;
        bits += 8;

        while (bits >= 5) {
            bits -= 5;
            result += BASE32_ALPHABET[(buffer >> bits) & 0x1F];
        }
    }

    if (bits > 0) {
        result += BASE32_ALPHABET[(buffer << (5 - bits)) & 0x1F];
    }

    return result;
}

// Base32 decoding
Result<std::vector<uint8_t>> Base32Decode(const std::string& encoded) {
    std::vector<uint8_t> result;
    result.reserve((encoded.size() * 5) / 8);

    uint32_t buffer = 0;
    int bits = 0;

    for (char c : encoded) {
        // Skip underscores
        if (c == '_') continue;

        // Find character in alphabet
        int value = -1;
        if (c >= 'A' && c <= 'Z') {
            value = c - 'A';
        } else if (c >= '2' && c <= '7') {
            value = 26 + (c - '2');
        }

        if (value == -1) {
            return Result<std::vector<uint8_t>>(
                Error(ErrorCode::InvalidArgument, std::string("Invalid Base32 character: ") + c));
        }

        buffer = (buffer << 5) | value;
        bits += 5;

        if (bits >= 8) {
            bits -= 8;
            result.push_back((buffer >> bits) & 0xFF);
        }
    }

    return Result<std::vector<uint8_t>>(std::move(result));
}

}  // anonymous namespace

// SLIP10::Key implementation

std::vector<uint8_t> SLIP10::Key::GetPublicKey() const {
    std::vector<uint8_t> public_key(crypto_sign_PUBLICKEYBYTES);
    std::vector<uint8_t> secret_key(crypto_sign_SECRETKEYBYTES);

    // Ed25519 secret key = 32-byte seed + 32-byte public key
    crypto_sign_seed_keypair(public_key.data(), secret_key.data(), key.data());

    return public_key;
}

Result<SLIP10::Key> SLIP10::Key::Derive(uint32_t index) const {
    // Ed25519 only supports hardened derivation
    if (index < SLIP10::HARDENED_OFFSET) {
        return Result<Key>(
            Error(ErrorCode::InvalidArgument, "Ed25519 requires hardened derivation (index >= 0x80000000)"));
    }

    // Build data: 0x00 || key (32 bytes) || index (4 bytes, big-endian)
    std::vector<uint8_t> data;
    data.reserve(37);
    data.push_back(0x00);
    data.insert(data.end(), key.begin(), key.end());

    uint32_t index_be = __builtin_bswap32(index);
    const uint8_t* index_bytes = reinterpret_cast<const uint8_t*>(&index_be);
    data.insert(data.end(), index_bytes, index_bytes + 4);

    // HMAC-SHA512(chain_code, data)
    std::vector<uint8_t> chain_code_vec(chain_code.begin(), chain_code.end());
    auto hmac_result = HMAC_SHA512(chain_code_vec, data);

    Key child_key;
    std::copy(hmac_result.begin(), hmac_result.begin() + 32, child_key.key.begin());
    std::copy(hmac_result.begin() + 32, hmac_result.end(), child_key.chain_code.begin());

    return Result<Key>(std::move(child_key));
}

// SLIP10 implementation

Result<SLIP10::Key> SLIP10::NewMasterKey(const std::vector<uint8_t>& seed) {
    if (seed.empty()) {
        return Result<Key>(
            Error(ErrorCode::InvalidArgument, "Seed cannot be empty"));
    }

    std::vector<uint8_t> modifier(ED25519_SEED_MODIFIER,
                                   ED25519_SEED_MODIFIER + strlen(ED25519_SEED_MODIFIER));

    auto hmac_result = HMAC_SHA512(modifier, seed);

    Key master_key;
    std::copy(hmac_result.begin(), hmac_result.begin() + 32, master_key.key.begin());
    std::copy(hmac_result.begin() + 32, hmac_result.end(), master_key.chain_code.begin());

    return Result<Key>(std::move(master_key));
}

Result<uint32_t> SLIP10::ParsePathSegment(const std::string& segment) {
    bool hardened = segment.back() == '\'';
    std::string number_str = hardened ? segment.substr(0, segment.size() - 1) : segment;

    try {
        uint64_t index = std::stoull(number_str);
        if (index >= HARDENED_OFFSET) {
            return Result<uint32_t>(
                Error(ErrorCode::InvalidArgument, "Path index too large"));
        }

        if (hardened) {
            index += HARDENED_OFFSET;
        }

        return Result<uint32_t>(static_cast<uint32_t>(index));
    } catch (...) {
        return Result<uint32_t>(
            Error(ErrorCode::InvalidArgument, "Invalid path segment: " + segment));
    }
}

bool SLIP10::IsValidPath(const std::string& path) {
    std::regex path_regex("^m(/[0-9]+')+$");
    if (!std::regex_match(path, path_regex)) {
        return false;
    }

    // Check for overflows
    std::istringstream ss(path);
    std::string segment;
    std::getline(ss, segment, '/');  // Skip 'm'

    while (std::getline(ss, segment, '/')) {
        auto result = ParsePathSegment(segment);
        if (!result.IsOk()) {
            return false;
        }
    }

    return true;
}

Result<SLIP10::Key> SLIP10::DeriveForPath(const std::string& path, const std::vector<uint8_t>& seed) {
    if (!IsValidPath(path)) {
        return Result<Key>(
            Error(ErrorCode::InvalidArgument, "Invalid derivation path: " + path));
    }

    auto master_result = NewMasterKey(seed);
    if (!master_result.IsOk()) {
        return master_result;
    }

    Key key = master_result.Value();

    // Parse and derive each segment
    std::istringstream ss(path);
    std::string segment;
    std::getline(ss, segment, '/');  // Skip 'm'

    while (std::getline(ss, segment, '/')) {
        auto index_result = ParsePathSegment(segment);
        if (!index_result.IsOk()) {
            return Result<Key>(index_result.GetError());
        }

        auto derive_result = key.Derive(index_result.Value());
        if (!derive_result.IsOk()) {
            return derive_result;
        }

        key = derive_result.Value();
    }

    return Result<Key>(std::move(key));
}

Result<SLIP10::Key> SLIP10::DeriveZoobcAccount(uint32_t account_index, const std::vector<uint8_t>& seed) {
    std::ostringstream path_stream;
    path_stream << "m/44'/" << ZOOBC_COIN_TYPE << "'/" << account_index << "'";
    return DeriveForPath(path_stream.str(), seed);
}

// PBKDF2-HMAC-SHA512 implementation (BIP-39 requires exactly this)
std::vector<uint8_t> PBKDF2_HMAC_SHA512(
    const std::string& password,
    const std::string& salt,
    int iterations,
    size_t dkLen) {

    std::vector<uint8_t> derived_key(dkLen);

    // PBKDF2 algorithm: DK = T1 || T2 || ... || Tdklen/hlen
    // Where Ti = F(Password, Salt, iterations, i)
    // F(Password, Salt, c, i) = U1 xor U2 xor ... xor Uc
    // U1 = PRF(Password, Salt || INT_32_BE(i))
    // Uj = PRF(Password, Uj-1)

    const size_t hLen = 64;  // SHA-512 output is 64 bytes
    size_t blocks_needed = (dkLen + hLen - 1) / hLen;

    for (size_t block = 1; block <= blocks_needed; block++) {
        // Prepare salt || INT_32_BE(block)
        std::vector<uint8_t> salt_block;
        salt_block.insert(salt_block.end(), salt.begin(), salt.end());

        // Append block number as big-endian 32-bit integer
        uint32_t block_be = __builtin_bswap32(static_cast<uint32_t>(block));
        const uint8_t* block_bytes = reinterpret_cast<const uint8_t*>(&block_be);
        salt_block.insert(salt_block.end(), block_bytes, block_bytes + 4);

        // U1 = PRF(password, salt || block)
        std::vector<uint8_t> password_vec(password.begin(), password.end());
        auto U = HMAC_SHA512(password_vec, salt_block);
        std::array<uint8_t, 64> T = U;  // T = U1

        // U2..Uc
        for (int i = 1; i < iterations; i++) {
            std::vector<uint8_t> U_vec(U.begin(), U.end());
            U = HMAC_SHA512(password_vec, U_vec);

            // T = T xor Ui
            for (size_t j = 0; j < hLen; j++) {
                T[j] ^= U[j];
            }
        }

        // Copy to output
        size_t offset = (block - 1) * hLen;
        size_t copy_len = std::min(hLen, dkLen - offset);
        std::copy(T.begin(), T.begin() + copy_len, derived_key.begin() + offset);
    }

    return derived_key;
}

// BIP39 implementation

Result<std::vector<uint8_t>> BIP39::MnemonicToSeed(const std::string& mnemonic, const std::string& password) {
    // BIP-39 specification:
    // seed = PBKDF2(PRF = HMAC-SHA512, Password = mnemonic, Salt = "mnemonic" + passphrase, iterations = 2048, dkLen = 64 bytes)
    std::string salt = "mnemonic" + password;

    auto seed = PBKDF2_HMAC_SHA512(mnemonic, salt, 2048, 64);

    return Result<std::vector<uint8_t>>(std::move(seed));
}

// BIP-39 English wordlist (2048 words)
static const char* BIP39_WORDLIST[] = {
    "abandon","ability","able","about","above","absent","absorb","abstract","absurd","abuse",
    "access","accident","account","accuse","achieve","acid","acoustic","acquire","across","act",
    "action","actor","actress","actual","adapt","add","addict","address","adjust","admit",
    "adult","advance","advice","aerobic","affair","afford","afraid","again","age","agent",
    "agree","ahead","aim","air","airport","aisle","alarm","album","alcohol","alert",
    "alien","all","alley","allow","almost","alone","alpha","already","also","alter",
    "always","amateur","amazing","among","amount","amused","analyst","anchor","ancient","anger",
    "angle","angry","animal","ankle","announce","annual","another","answer","antenna","antique",
    "anxiety","any","apart","apology","appear","apple","approve","april","arch","arctic",
    "area","arena","argue","arm","armed","armor","army","around","arrange","arrest",
    "arrive","arrow","art","artefact","artist","artwork","ask","aspect","assault","asset",
    "assist","assume","asthma","athlete","atom","attack","attend","attitude","attract","auction",
    "audit","august","aunt","author","auto","autumn","average","avocado","avoid","awake",
    "aware","away","awesome","awful","awkward","axis","baby","bachelor","bacon","badge",
    "bag","balance","balcony","ball","bamboo","banana","banner","bar","barely","bargain",
    "barrel","base","basic","basket","battle","beach","bean","beauty","because","become",
    "beef","before","begin","behave","behind","believe","below","belt","bench","benefit",
    "best","betray","better","between","beyond","bicycle","bid","bike","bind","biology",
    "bird","birth","bitter","black","blade","blame","blanket","blast","bleak","bless",
    "blind","blood","blossom","blouse","blue","blur","blush","board","boat","body",
    "boil","bomb","bone","bonus","book","boost","border","boring","borrow","boss",
    "bottom","bounce","box","boy","bracket","brain","brand","brass","brave","bread",
    "breeze","brick","bridge","brief","bright","bring","brisk","broccoli","broken","bronze",
    "broom","brother","brown","brush","bubble","buddy","budget","buffalo","build","bulb",
    "bulk","bullet","bundle","bunker","burden","burger","burst","bus","business","busy",
    "butter","buyer","buzz","cabbage","cabin","cable","cactus","cage","cake","call",
    "calm","camera","camp","can","canal","cancel","candy","cannon","canoe","canvas",
    "canyon","capable","capital","captain","car","carbon","card","cargo","carpet","carry",
    "cart","case","cash","casino","castle","casual","cat","catalog","catch","category",
    "cattle","caught","cause","caution","cave","ceiling","celery","cement","census","century",
    "cereal","certain","chair","chalk","champion","change","chaos","chapter","charge","chase",
    "chat","cheap","check","cheese","chef","cherry","chest","chicken","chief","child",
    "chimney","choice","choose","chronic","chuckle","chunk","churn","cigar","cinnamon","circle",
    "citizen","city","civil","claim","clap","clarify","claw","clay","clean","clerk",
    "clever","click","client","cliff","climb","clinic","clip","clock","clog","close",
    "cloth","cloud","clown","club","clump","cluster","clutch","coach","coast","coconut",
    "code","coffee","coil","coin","collect","color","column","combine","come","comfort",
    "comic","common","company","concert","conduct","confirm","congress","connect","consider","control",
    "convince","cook","cool","copper","copy","coral","core","corn","correct","cost",
    "cotton","couch","country","couple","course","cousin","cover","coyote","crack","cradle",
    "craft","cram","crane","crash","crater","crawl","crazy","cream","credit","creek",
    "crew","cricket","crime","crisp","critic","crop","cross","crouch","crowd","crucial",
    "cruel","cruise","crumble","crunch","crush","cry","crystal","cube","culture","cup",
    "cupboard","curious","current","curtain","curve","cushion","custom","cute","cycle","dad",
    "damage","damp","dance","danger","daring","dash","daughter","dawn","day","deal",
    "debate","debris","decade","december","decide","decline","decorate","decrease","deer","defense",
    "define","defy","degree","delay","deliver","demand","demise","denial","dentist","deny",
    "depart","depend","deposit","depth","deputy","derive","describe","desert","design","desk",
    "despair","destroy","detail","detect","develop","device","devote","diagram","dial","diamond",
    "diary","dice","diesel","diet","differ","digital","dignity","dilemma","dinner","dinosaur",
    "direct","dirt","disagree","discover","disease","dish","dismiss","disorder","display","distance",
    "divert","divide","divorce","dizzy","doctor","document","dog","doll","dolphin","domain",
    "donate","donkey","donor","door","dose","double","dove","draft","dragon","drama",
    "drastic","draw","dream","dress","drift","drill","drink","drip","drive","drop",
    "drum","dry","duck","dumb","dune","during","dust","dutch","duty","dwarf",
    "dynamic","eager","eagle","early","earn","earth","easily","east","easy","echo",
    "ecology","economy","edge","edit","educate","effort","egg","eight","either","elbow",
    "elder","electric","elegant","element","elephant","elevator","elite","else","embark","embody",
    "embrace","emerge","emotion","employ","empower","empty","enable","enact","end","endless",
    "endorse","enemy","energy","enforce","engage","engine","enhance","enjoy","enlist","enough",
    "enrich","enroll","ensure","enter","entire","entry","envelope","episode","equal","equip",
    "era","erase","erode","erosion","error","erupt","escape","essay","essence","estate",
    "eternal","ethics","evidence","evil","evoke","evolve","exact","example","excess","exchange",
    "excite","exclude","excuse","execute","exercise","exhaust","exhibit","exile","exist","exit",
    "exotic","expand","expect","expire","explain","expose","express","extend","extra","eye",
    "eyebrow","fabric","face","faculty","fade","faint","faith","fall","false","fame",
    "family","famous","fan","fancy","fantasy","farm","fashion","fat","fatal","father",
    "fatigue","fault","favorite","feature","february","federal","fee","feed","feel","female",
    "fence","festival","fetch","fever","few","fiber","fiction","field","figure","file",
    "film","filter","final","find","fine","finger","finish","fire","firm","first",
    "fiscal","fish","fit","fitness","fix","flag","flame","flash","flat","flavor",
    "flee","flight","flip","float","flock","floor","flower","fluid","flush","fly",
    "foam","focus","fog","foil","fold","follow","food","foot","force","forest",
    "forget","fork","fortune","forum","forward","fossil","foster","found","fox","fragile",
    "frame","frequent","fresh","friend","fringe","frog","front","frost","frown","frozen",
    "fruit","fuel","fun","funny","furnace","fury","future","gadget","gain","galaxy",
    "gallery","app","gap","garage","garbage","garden","garlic","garment","gas","gasp",
    "gate","gather","gauge","gaze","general","genius","genre","gentle","genuine","gesture",
    "ghost","giant","gift","giggle","ginger","giraffe","girl","give","glad","glance",
    "glare","glass","glide","glimpse","globe","gloom","glory","glove","glow","glue",
    "goat","goddess","gold","good","goose","gorilla","gospel","gossip","govern","gown",
    "grab","grace","grain","grant","grape","grass","gravity","great","green","grid",
    "grief","grit","grocery","group","grow","grunt","guard","guess","guide","guilt",
    "guitar","gun","gym","habit","hair","half","hammer","hamster","hand","happy",
    "harbor","hard","harsh","harvest","hat","have","hawk","hazard","head","health",
    "heart","heavy","hedgehog","height","hello","helmet","help","hen","hero","hidden",
    "high","hill","hint","hip","hire","history","hobby","hockey","hold","hole",
    "holiday","hollow","home","honey","hood","hope","horn","horror","horse","hospital",
    "host","hotel","hour","hover","hub","huge","human","humble","humor","hundred",
    "hungry","hunt","hurdle","hurry","hurt","husband","hybrid","ice","icon","idea",
    "identify","idle","ignore","ill","illegal","illness","image","imitate","immense","immune",
    "impact","impose","improve","impulse","inch","include","income","increase","index","indicate",
    "indoor","industry","infant","inflict","inform","inhale","inherit","initial","inject","injury",
    "inmate","inner","innocent","input","inquiry","insane","insect","inside","inspire","install",
    "intact","interest","into","invest","invite","involve","iron","island","isolate","issue",
    "item","ivory","jacket","jaguar","jar","jazz","jealous","jeans","jelly","jewel",
    "job","join","joke","journey","joy","judge","juice","jump","jungle","junior",
    "junk","just","kangaroo","keen","keep","ketchup","key","kick","kid","kidney",
    "kind","kingdom","kiss","kit","kitchen","kite","kitten","kiwi","knee","knife",
    "knock","know","lab","label","labor","ladder","lady","lake","lamp","language",
    "laptop","large","later","latin","laugh","laundry","lava","law","lawn","lawsuit",
    "layer","lazy","leader","leaf","learn","leave","lecture","left","leg","legal",
    "legend","leisure","lemon","lend","length","lens","leopard","lesson","letter","level",
    "liar","liberty","library","license","life","lift","light","like","limb","limit",
    "link","lion","liquid","list","little","live","lizard","load","loan","lobster",
    "local","lock","logic","lonely","long","loop","lottery","loud","lounge","love",
    "loyal","lucky","luggage","lumber","lunar","lunch","luxury","lyrics","machine","mad",
    "magic","magnet","maid","mail","main","major","make","mammal","man","manage",
    "mandate","mango","mansion","manual","maple","marble","march","margin","marine","market",
    "marriage","mask","mass","master","match","material","math","matrix","matter","maximum",
    "maze","meadow","mean","measure","meat","mechanic","medal","media","melody","melt",
    "member","memory","mention","menu","mercy","merge","merit","merry","mesh","message",
    "metal","method","middle","midnight","milk","million","mimic","mind","minimum","minor",
    "minute","miracle","mirror","misery","miss","mistake","mix","mixed","mixture","mobile",
    "model","modify","mom","moment","monitor","monkey","monster","month","moon","moral",
    "more","morning","mosquito","mother","motion","motor","mountain","mouse","move","movie",
    "much","muffin","mule","multiply","muscle","museum","mushroom","music","must","mutual",
    "myself","mystery","myth","naive","name","napkin","narrow","nasty","nation","nature",
    "near","neck","need","negative","neglect","neither","nephew","nerve","nest","net",
    "network","neutral","never","news","next","nice","night","noble","noise","nominee",
    "noodle","normal","north","nose","notable","note","nothing","notice","novel","now",
    "nuclear","number","nurse","nut","oak","obey","object","oblige","obscure","observe",
    "obtain","obvious","occur","ocean","october","odor","off","offer","office","often",
    "oil","okay","old","olive","olympic","omit","once","one","onion","online",
    "only","open","opera","opinion","oppose","option","orange","orbit","orchard","order",
    "ordinary","organ","orient","original","orphan","ostrich","other","outdoor","outer","output",
    "outside","oval","oven","over","own","owner","oxygen","oyster","ozone","pact",
    "paddle","page","pair","palace","palm","panda","panel","panic","panther","paper",
    "parade","parent","park","parrot","party","pass","patch","path","patient","patrol",
    "pattern","pause","pave","payment","peace","peanut","pear","peasant","pelican","pen",
    "penalty","pencil","people","pepper","perfect","permit","person","pet","phone","photo",
    "phrase","physical","piano","picnic","picture","piece","pig","pigeon","pill","pilot",
    "pink","pioneer","pipe","pistol","pitch","pizza","place","planet","plastic","plate",
    "play","please","pledge","pluck","plug","plunge","poem","poet","point","polar",
    "pole","police","pond","pony","pool","popular","portion","position","possible","post",
    "potato","pottery","poverty","powder","power","practice","praise","predict","prefer","prepare",
    "present","pretty","prevent","price","pride","primary","print","priority","prison","private",
    "prize","problem","process","produce","profit","program","project","promote","proof","property",
    "prosper","protect","proud","provide","public","pudding","pull","pulp","pulse","pumpkin",
    "punch","pupil","puppy","purchase","purity","purpose","purse","push","put","puzzle",
    "pyramid","quality","quantum","quarter","question","quick","quit","quiz","quote","rabbit",
    "raccoon","race","rack","radar","radio","rail","rain","raise","rally","ramp",
    "ranch","random","range","rapid","rare","rate","rather","raven","raw","razor",
    "ready","real","reason","rebel","rebuild","recall","receive","recipe","record","recycle",
    "reduce","reflect","reform","refuse","region","regret","regular","reject","relax","release",
    "relief","rely","remain","remember","remind","remove","render","renew","rent","reopen",
    "repair","repeat","replace","report","require","rescue","resemble","resist","resource","response",
    "result","retire","retreat","return","reunion","reveal","review","reward","rhythm","rib",
    "ribbon","rice","rich","ride","ridge","rifle","right","rigid","ring","riot",
    "ripple","risk","ritual","rival","river","road","roast","robot","robust","rocket",
    "romance","roof","rookie","room","rose","rotate","rough","round","route","royal",
    "rubber","rude","rug","rule","run","runway","rural","sad","saddle","sadness",
    "safe","sail","salad","salmon","salon","salt","salute","same","sample","sand",
    "satisfy","satoshi","sauce","sausage","save","say","scale","scan","scare","scatter",
    "scene","scheme","school","science","scissors","scorpion","scout","scrap","screen","script",
    "scrub","sea","search","season","seat","second","secret","section","security","seed",
    "seek","segment","select","sell","seminar","senior","sense","sentence","series","service",
    "session","settle","setup","seven","shadow","shaft","shallow","share","shed","shell",
    "sheriff","shield","shift","shine","ship","shiver","shock","shoe","shoot","shop",
    "short","shoulder","shove","shrimp","shrug","shuffle","shy","sibling","sick","side",
    "siege","sight","sign","silent","silk","silly","silver","similar","simple","since",
    "sing","siren","sister","situate","six","size","skate","sketch","ski","skill",
    "skin","skirt","skull","slab","slam","sleep","slender","slice","slide","slight",
    "slim","slogan","slot","slow","slush","small","smart","smile","smoke","smooth",
    "snack","snake","snap","sniff","snow","soap","soccer","social","sock","soda",
    "soft","solar","soldier","solid","solution","solve","someone","song","soon","sorry",
    "sort","soul","sound","soup","source","south","space","spare","spatial","spawn",
    "speak","special","speed","spell","spend","sphere","spice","spider","spike","spin",
    "spirit","split","spoil","sponsor","spoon","sport","spot","spray","spread","spring",
    "spy","square","squeeze","squirrel","stable","stadium","staff","stage","stairs","stamp",
    "stand","start","state","stay","steak","steel","stem","step","stereo","stick",
    "still","sting","stock","stomach","stone","stool","story","stove","strategy","street",
    "strike","strong","struggle","student","stuff","stumble","style","subject","submit","subway",
    "success","such","sudden","suffer","sugar","suggest","suit","summer","sun","sunny",
    "sunset","super","supply","supreme","sure","surface","surge","surprise","surround","survey",
    "suspect","sustain","swallow","swamp","swap","swarm","swear","sweet","swift","swim",
    "swing","switch","sword","symbol","symptom","syrup","system","table","tackle","tag",
    "tail","talent","talk","tank","tape","target","task","taste","tattoo","taxi",
    "teach","team","tell","ten","tenant","tennis","tent","term","test","text",
    "thank","that","theme","then","theory","there","they","thing","this","thought",
    "three","thrive","throw","thumb","thunder","ticket","tide","tiger","tilt","timber",
    "time","tiny","tip","tired","tissue","title","toast","tobacco","today","toddler",
    "toe","together","toilet","token","tomato","tomorrow","tone","tongue","tonight","tool",
    "tooth","top","topic","topple","torch","tornado","tortoise","toss","total","tourist",
    "toward","tower","town","toy","track","trade","traffic","tragic","train","transfer",
    "trap","trash","travel","tray","treat","tree","trend","trial","tribe","trick",
    "trigger","trim","trip","trophy","trouble","truck","true","truly","trumpet","trust",
    "truth","try","tube","tuition","tumble","tuna","tunnel","turkey","turn","turtle",
    "twelve","twenty","twice","twin","twist","two","type","typical","ugly","umbrella",
    "unable","unaware","uncle","uncover","under","undo","unfair","unfold","unhappy","uniform",
    "unique","unit","universe","unknown","unlock","until","unusual","unveil","update","upgrade",
    "uphold","upon","upper","upset","urban","urge","usage","use","used","useful",
    "useless","usual","utility","vacant","vacuum","vague","valid","valley","valve","van",
    "vanish","vapor","various","vast","vault","vehicle","velvet","vendor","venture","venue",
    "verb","verify","version","very","vessel","veteran","viable","vibrant","vicious","victory",
    "video","view","village","vintage","violin","virtual","virus","visa","visit","visual",
    "vital","vivid","vocal","voice","void","volcano","volume","vote","voyage","wage",
    "wagon","wait","walk","wall","walnut","want","warfare","warm","warrior","wash",
    "wasp","waste","water","wave","way","wealth","weapon","wear","weasel","weather",
    "web","wedding","weekend","weird","welcome","west","wet","whale","what","wheat",
    "wheel","when","where","whip","whisper","wide","width","wife","wild","will",
    "win","window","wine","wing","wink","winner","winter","wire","wisdom","wise",
    "wish","witness","wolf","woman","wonder","wood","wool","word","work","world",
    "worry","worth","wrap","wreck","wrestle","wrist","write","wrong","yard","year",
    "yellow","you","young","youth","zebra","zero","zone","zoo"
};

Result<std::string> BIP39::GenerateMnemonic(int word_count) {
    // Validate word count
    if (word_count != 12 && word_count != 15 && word_count != 18 &&
        word_count != 21 && word_count != 24) {
        return Result<std::string>(
            Error(ErrorCode::InvalidArgument, "Word count must be 12, 15, 18, 21, or 24"));
    }

    // Calculate entropy size: word_count * 11 bits / 8 = entropy bytes
    // 12 words = 128 bits + 4 checksum = 16 bytes entropy
    // 24 words = 256 bits + 8 checksum = 32 bytes entropy
    int entropy_bits = (word_count * 11 * 32) / 33;  // Reverse: (ENT + CS) / 11 = words
    int entropy_bytes = entropy_bits / 8;

    // Generate random entropy
    std::vector<uint8_t> entropy(entropy_bytes);
    randombytes_buf(entropy.data(), entropy_bytes);

    // Calculate checksum: first (entropy_bits / 32) bits of SHA-256
    std::array<uint8_t, 32> hash;
    crypto_hash_sha256(hash.data(), entropy.data(), entropy_bytes);

    int checksum_bits = entropy_bits / 32;

    // Concatenate entropy + checksum into bit array
    std::vector<bool> bits;
    bits.reserve(entropy_bits + checksum_bits);

    // Add entropy bits
    for (int i = 0; i < entropy_bytes; i++) {
        for (int j = 7; j >= 0; j--) {
            bits.push_back((entropy[i] >> j) & 1);
        }
    }

    // Add checksum bits
    for (int i = 0; i < checksum_bits; i++) {
        bits.push_back((hash[0] >> (7 - i)) & 1);
    }

    // Split into 11-bit groups and convert to words
    std::string mnemonic;
    for (int i = 0; i < word_count; i++) {
        int index = 0;
        for (int j = 0; j < 11; j++) {
            index = (index << 1) | bits[i * 11 + j];
        }

        if (i > 0) {
            mnemonic += " ";
        }
        mnemonic += BIP39_WORDLIST[index];
    }

    return Result<std::string>(mnemonic);
}

bool BIP39::ValidateMnemonic(const std::string& mnemonic) {
    // Simplified validation: just check word count
    std::istringstream ss(mnemonic);
    int word_count = 0;
    std::string word;
    while (ss >> word) {
        word_count++;
    }

    return word_count == 12 || word_count == 15 || word_count == 18 ||
           word_count == 21 || word_count == 24;
}

// ZoobcAddress implementation

uint8_t ZoobcAddress::CalculateChecksum(const std::vector<uint8_t>& public_key) {
    // Legacy function - kept for compatibility
    // Real checksum is 3 bytes from SHA3-256
    uint32_t sum = 0;
    for (uint8_t byte : public_key) {
        sum += byte;
    }
    return static_cast<uint8_t>(sum & 0xFF);
}

std::string ZoobcAddress::Encode(const std::vector<uint8_t>& public_key, const std::string& prefix) {
    if (public_key.size() != 32) {
        return "";
    }
    if (prefix.length() != 3) {
        return "";
    }

    // ZooBC address format (from originals/lib-master/address/address.go):
    // 1. Create 35-byte buffer: public_key[32] + prefix[3]
    // 2. Hash with SHA3-256
    // 3. Take first 3 bytes of hash as checksum
    // 4. Replace prefix bytes with checksum bytes
    // 5. Base32 encode (56 characters)
    // 6. Format as: PREFIX_SEG1_SEG2_SEG3_SEG4_SEG5_SEG6_SEG7

    std::vector<uint8_t> buffer(35);

    // Copy public key
    std::copy(public_key.begin(), public_key.end(), buffer.begin());

    // Copy prefix (3 bytes)
    for (int i = 0; i < 3; i++) {
        buffer[32 + i] = static_cast<uint8_t>(prefix[i]);
    }

    // Compute SHA3-256 checksum (not SHA-256!)
    std::array<uint8_t, 32> hash;
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha3_256(), nullptr);
    EVP_DigestUpdate(mdctx, buffer.data(), buffer.size());
    unsigned int hash_len = 0;
    EVP_DigestFinal_ex(mdctx, hash.data(), &hash_len);
    EVP_MD_CTX_free(mdctx);

    // Replace prefix with first 3 bytes of checksum
    for (int i = 0; i < 3; i++) {
        buffer[32 + i] = hash[i];
    }

    // Encode to Base32 (35 bytes → 56 characters)
    std::string b32_encoded = Base32Encode(buffer);

    // Format as 7 segments of 8 characters each
    std::string result = prefix;
    for (int i = 0; i < 7; i++) {
        result += "_";
        result += b32_encoded.substr(i * 8, 8);
    }

    return result;
}

Result<std::vector<uint8_t>> ZoobcAddress::Decode(const std::string& address) {
    // ZooBC address format: PREFIX_SEG1_SEG2_SEG3_SEG4_SEG5_SEG6_SEG7
    // Canonical form: 66 characters (3 prefix + 1 sep + 56 base32 + 6 seps).
    //
    // Only the 59 SIGNIFICANT characters matter: the 3-letter prefix and the 56 base32 characters.
    // Everything between them is cosmetic — '_' and '-' (interchangeably, mixed), and whitespace,
    // which a line-wrapped paste or a chat client routinely inserts — and a form with no separators
    // at all is the same address. This is the rule the wallet applies before it decodes (strip
    // [-_\s], uppercase, then length + prefix + checksum); a string the wallet accepts must not be
    // refused one hop later by the node or a tool. Validity is still gated by the body length (56)
    // and the checksum, so no extra strings become valid beyond the same address written another way.
    std::string norm;
    norm.reserve(address.size());
    for (char c : address) {
        if (c == '_' || c == '-' || std::isspace(static_cast<unsigned char>(c))) continue;
        norm += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }

    if (norm.length() < 3) {
        return Result<std::vector<uint8_t>>(
            Error(ErrorCode::InvalidArgument, "Address too short"));
    }

    std::string prefix = norm.substr(0, 3);
    std::string b32_encoded = norm.substr(3);

    // Should be exactly 56 Base32 characters
    if (b32_encoded.length() != 56) {
        return Result<std::vector<uint8_t>>(
            Error(ErrorCode::InvalidArgument, "Invalid address encoding"));
    }

    // Decode from Base32
    auto decode_result = Base32Decode(b32_encoded);
    if (!decode_result.IsOk()) {
        return decode_result;
    }

    auto buffer = decode_result.Value();
    if (buffer.size() != 35) {
        return Result<std::vector<uint8_t>>(
            Error(ErrorCode::InvalidArgument, "Address must decode to 35 bytes"));
    }

    // Extract public key and checksum
    std::vector<uint8_t> public_key(buffer.begin(), buffer.begin() + 32);
    std::array<uint8_t, 3> input_checksum;
    for (int i = 0; i < 3; i++) {
        input_checksum[i] = buffer[32 + i];
    }

    // Recompute checksum to validate
    std::vector<uint8_t> verify_buffer(35);
    std::copy(public_key.begin(), public_key.end(), verify_buffer.begin());
    for (int i = 0; i < 3; i++) {
        verify_buffer[32 + i] = static_cast<uint8_t>(prefix[i]);
    }

    // Compute SHA3-256 checksum
    std::array<uint8_t, 32> hash;
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha3_256(), nullptr);
    EVP_DigestUpdate(mdctx, verify_buffer.data(), verify_buffer.size());
    unsigned int hash_len = 0;
    EVP_DigestFinal_ex(mdctx, hash.data(), &hash_len);
    EVP_MD_CTX_free(mdctx);

    // Verify checksum
    for (int i = 0; i < 3; i++) {
        if (hash[i] != input_checksum[i]) {
            return Result<std::vector<uint8_t>>(
                Error(ErrorCode::CryptoError, "Address checksum validation failed"));
        }
    }

    return Result<std::vector<uint8_t>>(std::move(public_key));
}

bool ZoobcAddress::IsFormatted(const std::string& address, const std::string& prefix) {
    // "Is this string a PREFIX address, however it is written?" — shape only; Decode() verifies.
    // Mirrors Decode's normalisation: the prefix is compared case-blind on the significant
    // characters, and after it either a separator ('_' or '-') follows in the written form, or the
    // string with separators and whitespace removed is exactly 59 characters of the base32
    // alphabet (the no-separator form the wallet accepts).
    if (prefix.length() != 3) return false;
    std::string norm;
    for (char c : address) {
        if (c == '_' || c == '-' || std::isspace(static_cast<unsigned char>(c))) continue;
        norm += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    if (norm.length() < 4) return false;
    for (int i = 0; i < 3; i++) {
        if (norm[i] != std::toupper(static_cast<unsigned char>(prefix[i]))) return false;
    }
    const size_t s = address.find_first_not_of(" \t\r\n");
    if (s != std::string::npos && address.length() > s + 3 && (address[s + 3] == '_' || address[s + 3] == '-')) return true;
    if (norm.length() != 59) return false;
    static const char* kAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    for (size_t i = 3; i < norm.length(); i++) {
        if (norm[i] == '\0' || std::strchr(kAlphabet, norm[i]) == nullptr) return false;
    }
    return true;
}

bool ZoobcAddress::ValidateChecksum(const std::string& address) {
    auto result = Decode(address);
    return result.IsOk();
}

}  // namespace crypto
}  // namespace zoobc
