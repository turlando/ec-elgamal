module Fixtures where

import Crypto.PubKey.ECC.Types (CurveName(..))
import Crypto.PubKey.ECC.Types (Point(..))
import Crypto.PubKey.ECC.Types (PrivateNumber, PublicPoint)

type Key = (CurveName, PrivateNumber, PublicPoint)

clearText :: Integer
clearText = 0x160c21f2

keys :: [Key]
keys =
  [ ( SEC_p112r1
    , 3569647606399654539638117999056162
    , Point 591846286983435523978407441263897
            3507399757127077688123504793602980
    )
  , ( SEC_p112r2
    , 294619145387201639595121156298465
    , Point 4109325583622823206562915235950561
            2840113886297949570978632095244306
    )
  , ( SEC_p128r2
    , 64077847468941579041686729166645555628
    , Point 209476190951274361381357981171497995621
            28141531513352758478556315377377743314
    )
  , ( SEC_p160r1
    , 406603724270427311148855946036826639761884942288
    , Point 1122275163315976611820825225496542532710381846823
            296180314512688096487153937007796349159675901467
    )
  , ( SEC_p192k1
    , 2009465079683891275135149801830697871678076120195625074526
    , Point 5390044616694850594717680965593366236215006477653552039533
            2321523524076506623671847842201720978821278042637865707987
    )
  , ( SEC_p224k1
    , 13736646486183582187276365953546431527412907937529961161221506336293
    , Point 18741545680162711538034048049772129338840510561187605709781733123403
            16050504325854877379039391378824322901848289156906491051035817072533
    )
  , ( SEC_p256k1
    , 56681172623519551479200252836990008957651473895153546535935120933333661205189
    , Point
      22625580930321955366896222313885804906834295323884891445260319226310992742164
      91182047336931948366694379947509210722467002820867006738264424636842533168415
    )
  , ( SEC_p384r1
    , 28105164211502710548956388710331951064563934656916866925300922720852440341789035605071540553860042459041472188581780
    , Point
      14089492148110015548582123056193007341283895653231004164264781132367338830389771261522212390930291056368170197826504
      15616945755368721886418146577117449341704148595372613841158462181028886697379965913802250246483132384987221529785406
    )
  , ( SEC_p521r1
    , 5923039644664093493429745114491074578352679596691715836522501915567223335310414802777329826701528826526769688167501423695863954899809716073812137603096195699
    , Point
      4283438551645028217251042736020052705426419043662976016159505805153268091389484718395020322231579364634053782009662815501265048742419022038248074788624903444
      101742623472958861177037713845183170893849461214111579621570981187439112971389008302438912523587166748983511475404604732343971668786606504713214844095252882
    )
  ]