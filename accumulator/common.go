package accumulator

import (
	crand "crypto/rand"
	"fmt"
	"math/big"
	"strconv"
)

const securityPara = 2048
const securityParaInBits = 128
const crs = "HKUST2021" //used as the seed for generating random numbers
const crsNum = 100      //used as the seed for generating random numbers
const PreComputeSize = 1000

// P2048String is p pre-generated using Init()
const P2048String = "63352778221927519361028463103750221448767352640233427497891399621493053762051700657931788556273902172185299032880373838940518063653253544038031035433413689867999659003837299132948209523942044375512707481879312162665398560984845365739680903745638207932972867945527614242168559637147989390689484323784675311291328928194683043070907622356523214367904866096427467353460642373184311945182134333502590473515421876528784622819173675165323917555281622848828732216045471000014824093521020555215602159615508774566425389790918241516894488428553979917141143240992021158121969388427052119009390574659447463689128757342765773031179"

// Q2048String is Q pre-generated using Init()
const Q2048String = "59707940779809277411480188346713486987786322075890848882681212552651535147347041858600702267103697910034498103090281481452195007294716841611148792278313240724971430538160966865945028411690792533734293937170131477146235663949930807323831815384770506308652874630713951574166340679413070918486581284856288630822952822926476418550089053774178490917593484489813875691708446764964322588153367956088348136772795599823562121090304264368839196743165966989555879340480782608319979980697857302959285327786831057616975461272702285468535178755806232777448654081877373753318605356456028828994661436304183282129548515081325811060163"

// N2048String is N pre-generated using Init()
const N2048String = "3782663930311239217608183347664343823344361883359316711879376052839589449986746417009731105842724371555587575090818821607315680690538322470192714094349843042038676524491545125292230625245803106242544492372054644071157555579882700958169992972371723299494069257459958650911911448225993251606101649307163080084475011418732048851452712010308214311139375231438728169780353620537664500226740151646487857904609395500230286136204531921408623327350056759272155995910031236688232871901380184722977493112939099457369340793434634433905842270269766750729169817036297962574179489320474102264294614467868830823290223990183140540740075758916813761019411105642243607628065544466984876051601928972128097431118808462143570159699929315722374715777383219088233937171408790201476549743967624838142201858790469897136027098432427038468258122468222438659666298283961502349186716809152566063067117344534634378461874486916997714670140594767065938092993565489439067873864295437491671833884003034957864602180037013767336827305619939595351805854111490733312109932725212289266908112898924421616363608554217990691877560857887013396712229297841700712493426963677473027748086973351482464941526120942545169848175563404519349499299808133554270745973052000377664043822177"

// G2048String is G pre-generated using Init()
const G2048String = "2414715160966861371882627981541692139805583626745478619926604782349555547492352685333015343108129508606784137137000846910510556373687726313213590112136913078823201533373268792127815816311690203443334205430078310415514716971850646563282624503142489223304125428071755412135897257379775185716918843705889432711911193029312812790843667653420891743800180953514140575389653564136843096815035559160396167192009871145682077521286630766162798131332978889083651584364317743279339238949886019132927110419822746149379025550616722696808914501494134961153160043651305698796728055427882823002661471810930862319582508595432549420211851647177133483886769723512269018628683964392717392134573047893768464602718783820315683032844427976597549430474018303684300815162667252728474523498825149053785341482465119353742068845051615869099302466207379267059377348501944398142384800111482984918864863601274844928118565558342575210822503066281108473200994599781396461954983752136760438009902597605258852248835978210167123515842758923228397770618954776774240153003888638548130010044958879306342629502029437344322676838425565328791453995370820102961584067129279733894327183810887728279983125584030005633121894046404405912551756949194728491335465989174703782420173326"

var one = big.NewInt(1)
var two = big.NewInt(2)
var Max2048 = big.NewInt(0)

// AccumulatorSetup is the struct to store parameters for a RSA accumulator,
// including private key pair (p,q), N = pq and generator g in QR
type AccumulatorSetup struct {
	P big.Int
	Q big.Int
	N big.Int
	G big.Int //generator in QR_N
}

type Element []byte

// Init generates a private key pair (p,q), and N = pq and one generator g in QR
func Init() *AccumulatorSetup {
	var p, q, N, g big.Int
	crand.Read([]byte(crs))
	p = *getSafePrime()
	q = *getSafePrime()
	N.Mul(&p, &q)
	g = *getRanQR(&p, &q)

	var ret AccumulatorSetup
	ret.P = p
	ret.Q = q
	ret.N = N
	ret.G = g
	return &ret
}

func SetWindowValue(inputSet []Element) []big.Int {
	setSize := len(inputSet)
	hashValues := make([]big.Int, setSize)
	ret := make([]big.Int, setSize)

	for i := 0; i < setSize; i++ {
		hashValues[i] = *SHA256ToInt(inputSet[i])
	}

	for windowSize := 0; windowSize < setSize; windowSize++ {
		ret[windowSize] = *WindowMulThenSum(hashValues, windowSize)
	}

	return ret
}

/* WindowMulThenSum calculates the sum of partial products of the input set.
For example, if the input set is x_1, x_2, x_3, x_4, and the windowSize is 2,
this function calculates x_1x_2 + x_1x_3 + x_1x_4 + x_2x_3 + x_2x_4 + x_3x_4.
If windowSize is 0, return 1.
*/
func WindowMulThenSum(inputSet []big.Int, windowSize int) *big.Int {
	var ret big.Int
	setSize := len(inputSet)
	if setSize < windowSize {
		fmt.Println("Error in MulThenSum, the windowSize is larger than set size")
		return &ret
	}
	if windowSize < 1 {
		if windowSize == 0 {
			return one
		}
		fmt.Println("Error in MulThenSum, the windowSize is less than 1")
		return &ret
	}
	if windowSize == 1 {
		ret = *SetSum(inputSet)
		return &ret
	}
	if setSize == windowSize {
		ret = *SetProduct(inputSet)
		return &ret
	}

	// setSize > windowSize
	var tempInt big.Int
	for i := 0; i < setSize-windowSize+1; i++ {
		tempInt = *WindowMulThenSum(inputSet[i+1:], windowSize-1)
		tempInt.Mul(&tempInt, &inputSet[i])
		ret.Add(&ret, &tempInt)
	}

	return &ret
}

// SetSum calculates the sum of the input set
func SetSum(inputSet []big.Int) *big.Int {
	var ret big.Int
	setSize := len(inputSet)
	// ret is set to zero by default
	for i := 0; i < setSize; i++ {
		ret.Add(&ret, &inputSet[i])
	}
	return &ret
}

// SetProduct calculates the products of the input set
func SetProduct(inputSet []big.Int) *big.Int {
	var ret big.Int
	setSize := len(inputSet)
	ret.Set(one)
	// ret is set to 1
	for i := 0; i < setSize; i++ {
		ret.Mul(&ret, &inputSet[i])
	}
	return &ret
}

// GetPseudoRandomElement returns the pseudo random element from the input integer, for test use only
func GetPseudoRandomElement(input int) *Element {
	var ret Element
	temp := strconv.Itoa(input)
	ret = []byte(temp[:])
	return &ret
}
