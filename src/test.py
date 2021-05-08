#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

from random import seed

#from P2021_Practica3_Skeleton import *
from main import *


class Test1_1_ElGamalKeyGen(unittest.TestCase):

    def test_elgamal_keygen_64bits(self):

        num_bits, num_its = 64, 20

        for _ in range(num_its):
            (k_priv, k_pub) = uoc_elgamal_keygen(num_bits)
            self.assertEqual(len(k_priv), 3)
            self.assertEqual(len(k_pub), 3)
            self.assertEqual(k_pub[0], k_priv[0])
            self.assertEqual(k_pub[1], k_priv[1])
            self.assertIsNotNone(k_pub[1])
            self.assertEqual(k_pub[2], pow(k_pub[1], k_priv[2], k_pub[0]))

    def test_elgamal_keygen_128bits(self):

        num_bits, num_its = 128, 20

        for _ in range(num_its):
            (k_priv, k_pub) = uoc_elgamal_keygen(num_bits)
            self.assertEqual(len(k_priv), 3)
            self.assertEqual(len(k_pub), 3)
            self.assertEqual(k_pub[0], k_priv[0])
            self.assertEqual(k_pub[1], k_priv[1])
            self.assertIsNotNone(k_pub[1])
            self.assertEqual(k_pub[2], pow(k_pub[1], k_priv[2], k_pub[0]))

    def test_elgamal_keygen_256bits(self):

        num_bits, num_its = 256, 2

        for _ in range(num_its):
            (k_priv, k_pub) = uoc_elgamal_keygen(num_bits)
            self.assertEqual(len(k_priv), 3)
            self.assertEqual(len(k_pub), 3)
            self.assertEqual(k_pub[0], k_priv[0])
            self.assertEqual(k_pub[1], k_priv[1])
            self.assertIsNotNone(k_pub[1])
            self.assertEqual(k_pub[2], pow(k_pub[1], k_priv[2], k_pub[0]))




class Test1_2_ElGamalSign(unittest.TestCase):

    def test_elgamal_sign_fixedk_1(self):
        m = 42
        k_priv = (141627058957340093855620484680587497231, 49407674567884478422262585667470127500,
                  91557801542207645804476483173676169513)
        k_pub = (141627058957340093855620484680587497231, 49407674567884478422262585667470127500,
                 136166465183429483437614516541235447540)
        h = 6505205550934361491179720631243
        exp_r = 16070586247864526048715174304611921161
        exp_s = 79906657969558945308772045181673566953
        (r, s) = uoc_elgamal_sign(k_priv, m, h)
        self.assertEqual(r, exp_r)
        self.assertEqual(s, exp_s)

    def test_elgamal_sign_fixedk_2(self):
        m = 42424242
        k_priv = (12992917616897605511470512010377760999, 6497100366721531782651229087612454514,
                  8184645315919973579263902520077142907)
        k_pub = (12992917616897605511470512010377760999, 6497100366721531782651229087612454514,
                 4784536271623967017080018506651914749)
        h = 30541127218530291833593754023
        exp_r = 370282987414176508036351785758150113
        exp_s = 57221387644974029881195998309189883
        (r, s) = uoc_elgamal_sign(k_priv, m, h)
        self.assertEqual(r, exp_r)
        self.assertEqual(s, exp_s)

    def test_elgamal_sign_fixedk_3(self):
        m = 123456789
        k_priv = (111095862244100561185773259658903092441, 68715015864842833415840443685753818922,
                  10688562822627073336062911686899436628)
        k_pub = (111095862244100561185773259658903092441, 68715015864842833415840443685753818922,
                 37400235185594015815971136915025528910)
        h = 6235123811656012209298405325689
        exp_r = 16165481899748746481848784352851142527
        exp_s = 98809740663833529553705269007330012337
        (r, s) = uoc_elgamal_sign(k_priv, m, h)
        self.assertEqual(r, exp_r)
        self.assertEqual(s, exp_s)

    def test_elgamal_sign_fixedk_4(self):
        m = 123456789123456789123456789
        k_priv = (112847941112170644296267772277509350846555975113583168624796765318122631009049,
                  8727126823951345831686546296722679628937575768766379507115329576365730863802,
                  90254950644239289915262816357689053461511329394130471493737946140216700916566)
        k_pub = (112847941112170644296267772277509350846555975113583168624796765318122631009049,
                 8727126823951345831686546296722679628937575768766379507115329576365730863802,
                 2099965966935399988641793851392022051292773481845879860193310339903489213462)
        h = 2294742374266784531203391331539988254350495938206389588496594528290435
        exp_r = 5243953816691648242050551475605541294498933363835245262768302013908462924792
        exp_s = 72567626378663072501746825375182155635676274934487883661122801069515340587487
        (r, s) = uoc_elgamal_sign(k_priv, m, h)
        self.assertEqual(r, exp_r)
        self.assertEqual(s, exp_s)




class Test1_3_ElGamalVerify(unittest.TestCase):

    def test_elgamal_verify_ok_1(self):
        k_pub = (141627058957340093855620484680587497231, 49407674567884478422262585667470127500,
                 136166465183429483437614516541235447540)
        r = 16070586247864526048715174304611921161
        s = 79906657969558945308772045181673566953
        m = 42
        result = uoc_elgamal_verify((r, s), k_pub, m)
        self.assertEqual(result, True)

    def test_elgamal_verify_ok_2(self):
        k_pub = (12992917616897605511470512010377760999, 6497100366721531782651229087612454514,
                 4784536271623967017080018506651914749)
        r = 370282987414176508036351785758150113
        s = 57221387644974029881195998309189883
        m = 42424242
        result = uoc_elgamal_verify((r, s), k_pub, m)
        self.assertEqual(result, True)

    def test_elgamal_verify_ok_3(self):
        k_pub = (111095862244100561185773259658903092441, 68715015864842833415840443685753818922,
                 37400235185594015815971136915025528910)
        r = 16165481899748746481848784352851142527
        s = 98809740663833529553705269007330012337
        m = 123456789
        result = uoc_elgamal_verify((r, s), k_pub, m)
        self.assertEqual(result, True)

    def test_elgamal_verify_ok_4(self):
        k_pub = (112847941112170644296267772277509350846555975113583168624796765318122631009049,
                 8727126823951345831686546296722679628937575768766379507115329576365730863802,
                 2099965966935399988641793851392022051292773481845879860193310339903489213462)
        r = 5243953816691648242050551475605541294498933363835245262768302013908462924792
        s = 72567626378663072501746825375182155635676274934487883661122801069515340587487
        m = 123456789123456789123456789
        result = uoc_elgamal_verify((r, s), k_pub, m)
        self.assertEqual(result, True)

    def test_elgamal_verify_false_1(self):
        k_pub = (141627058957340093855620484680587497231, 49407674567884478422262585667470127500,
                 136166465183429483437614516541235447540)
        r = 16070586247864526048715174304611921161
        s = 79906657969558945308772045181673566954
        m = 42
        result = uoc_elgamal_verify((r, s), k_pub, m)
        self.assertEqual(result, False)

    def test_elgamal_verify_false_3(self):
        k_pub = (12992917616897605511470512010377760999, 6497100366721531782651229087612454514,
                 4784536271623967017080018506651914749)
        r = 370282987414176508036351785758150115
        s = 57221387644974029881195998309189883
        m = 42424242
        result = uoc_elgamal_verify((r, s), k_pub, m)
        self.assertEqual(result, False)

    def test_elgamal_verify_false_4(self):
        k_pub = (111095862244100561185773259658903092443, 68715015864842833415840443685753818922,
                 37400235185594015815971136915025528910)
        r = 16165481899748746481848784352851142527
        s = 98809740663833529553705269007330012337
        m = 123456789
        result = uoc_elgamal_verify((r, s), k_pub, m)
        self.assertEqual(result, False)

    def test_elgamal_verify_false_5(self):
        k_pub = (112847941112170644296267772277509350846555975113583168624796765318122631009049,
                 8727126823951345831686546296722679628937575768766379507115329576365730863803,
                 2099965966935399988641793851392022051292773481845879860193310339903489213462)
        r = 5243953816691648242050551475605541294498933363835245262768302013908462924792
        s = 72567626378663072501746825375182155635676274934487883661122801069515340587487
        m = 123456789123456789123456789
        result = uoc_elgamal_verify((r, s), k_pub, m)
        self.assertEqual(result, False)




class Test1_4_ElGamalExtractPrivKey(unittest.TestCase):

    def test_elgamal_extract_privkey_ok_1(self):
        exp_k_priv = (1736419493, 423105914, 1439798331)
        k_pub = (1736419493, 423105914, 1388681513)
        m1, m2 = 4321, 1234
        sig1 = (1670801833, 813531998)
        sig2 = (1670801833, 1514976703)
        extracted_k_priv = uoc_elgamal_extract_private_key(k_pub, m1, sig1, m2, sig2)
        self.assertEqual(extracted_k_priv, exp_k_priv)

    def test_elgamal_extract_privkey_ok_2(self):
        exp_k_priv = (3043480277, 949971850, 2984002184)
        k_pub = (3043480277, 949971850, 450506446)
        m1, m2 = 4321, 1234
        sig1 = (652612267, 1904199797)
        sig2 = (652612267, 716941154)
        extracted_k_priv = uoc_elgamal_extract_private_key(k_pub, m1, sig1, m2, sig2)
        self.assertEqual(extracted_k_priv, exp_k_priv)

    def test_elgamal_extract_privkey_ok_3(self):
        exp_k_priv = (3081644339, 432364326, 231991852)
        k_pub = (3081644339, 432364326, 1072654913)
        m1, m2 = 4321, 1234
        sig1 = (2294114827, 97380409)
        sig2 = (2294114827, 744220606)
        extracted_k_priv = uoc_elgamal_extract_private_key(k_pub, m1, sig1, m2, sig2)
        self.assertEqual(extracted_k_priv, exp_k_priv)

    def test_elgamal_extract_privkey_fail_1(self):
        exp_k_priv = -1
        k_pub = (1400337509, 1359471971, 45907697)
        m1, m2 = 4321, 4321
        sig1 = (639541257, 1115934695)
        sig2 = (639541257, 1115934695)
        extracted_k_priv = uoc_elgamal_extract_private_key(k_pub, m1, sig1, m2, sig2)
        self.assertEqual(extracted_k_priv, exp_k_priv)

    def test_elgamal_extract_privkey_fail_2(self):
        exp_k_priv = -1
        k_pub = (2056635443, 830686420, 1880350451)
        m1, m2 = 4321, 1234
        sig1 = (1601254651, 1061368902)
        sig2 = (1601254651, 935119992)
        extracted_k_priv = uoc_elgamal_extract_private_key(k_pub, m1, sig1, m2, sig2)
        self.assertEqual(extracted_k_priv, exp_k_priv)

    def test_elgamal_extract_privkey_fail_3(self):
        exp_k_priv = -1
        m1, m2 = 4321, 1234
        k_pub = (460730117, 91503345, 401055661)
        sig1 = (457648992, 18325781)
        sig2 = (457648992, 180721743)
        extracted_k_priv = uoc_elgamal_extract_private_key(k_pub, m1, sig1, m2, sig2)
        self.assertEqual(extracted_k_priv, exp_k_priv)

    def test_elgamal_extract_privkey_fail_4(self):
        exp_k_priv = -1
        m1, m2 = 4321, 1234
        k_pub = (3342796253, 1046051573, 77303856)
        sig1 = (1629150615, 2477614166)
        sig2 = (1462514112, 61485630)
        extracted_k_priv = uoc_elgamal_extract_private_key(k_pub, m1, sig1, m2, sig2)
        self.assertEqual(extracted_k_priv, exp_k_priv)





class Test2_1_0_ZkpProverInit(unittest.TestCase):

    def test_init_prover_ok_1(self):
        # 16 bits prime
        p, g, y, x = 28643, 1257, 3406, 28285
        prover = UocZkpProver(p, g, y, x)
        self.assertEqual(prover.p, p)
        self.assertEqual(prover.g, g)
        self.assertEqual(prover.y, y)
        self.assertEqual(prover.x, x)

    def test_init_prover_ok_2(self):
        # 64 bits prime
        p, g, y, x = 7687815937255549241, 27, 828418027377238633, 6041213497581640253
        prover = UocZkpProver(p, g, y, x)
        self.assertEqual(prover.p, p)
        self.assertEqual(prover.g, g)
        self.assertEqual(prover.y, y)
        self.assertEqual(prover.x, x)

    def test_init_prover_err_1(self):
        # p is not prime
        p, g, y, x = 3940176789, 1104176621, 3134867502, 1319732750
        self.assertRaises(InvalidParams, UocZkpProver, p, g, y, x)

    def test_init_prover_err_2(self):
        # g^x != y
        p, g, y, x = 6327248064174599447, 125, 576829006518034967, 3995005240860016868
        self.assertRaises(InvalidParams, UocZkpProver, p, g, y, x)

    def test_init_prover_err_3(self):
        # g is not a generator
        p, g, y, x = 5983462085168289047, 931322574615478515625, 914028363731158998, 3840904986799299867
        self.assertRaises(InvalidParams, UocZkpProver, p, g, y, x)





class Test2_1_ZkpProverComputeC(unittest.TestCase):

    def test_1(self):
        # 16 bits prime
        # Warning: this test assumes randint is used to chose r. If other methods
        # are used, the test may fail (and this does not necessarily mean compute_c
        # is not correctly implemented)
        seed(a=123456)
        p, g, y, x = 28643, 1257, 3406, 28285
        prover = UocZkpProver(p, g, y, x)
        c = prover.compute_c()

        # Python2
        # self.assertEqual(prover.r, 23075)
        # self.assertEqual(c, 928)
        self.assertEqual(prover.r, 26400)
        self.assertEqual(c, 24516)

    def test_2(self):
        # 64 bits prime
        # Warning: this test assumes randint is used to chose r. If other methods
        # are used, the test may fail (and this does not necessarily mean compute_c
        # is not correctly implemented)
        seed(a=654321)
        p, g, y, x = 7687815937255549241, 27, 828418027377238633, 6041213497581640253
        prover = UocZkpProver(p, g, y, x)
        c = prover.compute_c()
        self.assertEqual(prover.r, 4372826025337746426)
        self.assertEqual(c, 2394546805488415621)




class Test2_2_ZkpProverComputeH(unittest.TestCase):

    def test_b1_1(self):
        # 16 bits prime
        p, g, y, x = 28643, 1257, 3406, 28285
        prover = UocZkpProver(p, g, y, x)
        prover.r = 19440
        self.assertEqual(prover.compute_h(1), 19083)

    def test_b1_2(self):
        # 64 bits prime
        p, g, y, x = 7687815937255549241, 27, 828418027377238633, 6041213497581640253
        prover = UocZkpProver(p, g, y, x)
        prover.r = 7609375559171172593
        self.assertEqual(prover.compute_h(1), 5962773119497263606)

    def test_b0_1(self):
        # 16 bits prime
        p, g, y, x = 28643, 1257, 3406, 28285
        prover = UocZkpProver(p, g, y, x)
        prover.r = 7224
        self.assertEqual(prover.compute_h(0), 7224)

    def test_b0_2(self):
        # 64 bits prime
        p, g, y, x = 7687815937255549241, 27, 828418027377238633, 6041213497581640253
        prover = UocZkpProver(p, g, y, x)
        prover.r = 2077516426880017979
        self.assertEqual(prover.compute_h(0), 2077516426880017979)




class Test2_3_0_kpVerifierInit(unittest.TestCase):

    def test_init_verifier_ok_1(self):
        # 16 bits prime
        p, g, y = 28643, 1257, 3406
        verifier = UocZkpVerifier(p, g, y)
        self.assertEqual(verifier.p, p)
        self.assertEqual(verifier.g, g)
        self.assertEqual(verifier.y, y)

    def test_init_verifier_ok_2(self):
        # 64 bits prime
        p, g, y = 7687815937255549241, 27, 828418027377238633
        verifier = UocZkpVerifier(p, g, y)
        self.assertEqual(verifier.p, p)
        self.assertEqual(verifier.g, g)
        self.assertEqual(verifier.y, y)

    def test_init_verifier_err_1(self):
        # p is not prime
        p, g, y = 3940176789, 1104176621, 3134867502
        self.assertRaises(InvalidParams, UocZkpVerifier, p, g, y)

    def test_init_verifier_err_2(self):
        # g is not a generator
        p, g, y = 5983462085168289047, 931322574615478515625, 914028363731158998
        self.assertRaises(InvalidParams, UocZkpVerifier, p, g, y)




class Test2_3_ZkpVerifierChooseb(unittest.TestCase):

    def test_1(self):
        # 16 bits prime
        p, g, y = 28643, 1257, 3406
        verifier = UocZkpVerifier(p, g, y)
        c = 22668
        b = verifier.choose_b(c)
        self.assertEqual(verifier.c, c)
        self.assertEqual(verifier.b, b)
        self.assertTrue(0 <= b <= 1)

    def test_2(self):
        # 64 bits prime
        p, g, y = 7687815937255549241, 27, 828418027377238633
        verifier = UocZkpVerifier(p, g, y)
        c = 3726515057946724044
        b = verifier.choose_b(c)
        self.assertEqual(verifier.c, c)
        self.assertEqual(verifier.b, b)
        self.assertTrue(0 <= b <= 1)




class Test2_4_ZkpVerifierVerify(unittest.TestCase):

    def test_b0_1(self):
        # 16 bits prime
        p, g, y = 28643, 1257, 3406
        verifier = UocZkpVerifier(p, g, y)
        verifier.c = 1811
        verifier.b = 0
        h = 10863
        r = verifier.verify(h)
        self.assertTrue(r)

    def test_b0_2(self):
        # 16 bits prime
        p, g, y = 28643, 1257, 3406
        verifier = UocZkpVerifier(p, g, y)
        verifier.c = 22668
        verifier.b = 0
        h = 23236
        r = verifier.verify(h)
        self.assertTrue(r)

    def test_b0_3(self):
        # 64 bits prime
        p, g, y = 7687815937255549241, 27, 828418027377238633
        verifier = UocZkpVerifier(p, g, y)
        verifier.c = 7682733136308746968
        verifier.b = 0
        h = 699336931761820991
        r = verifier.verify(h)
        self.assertTrue(r)

    def test_b0_4(self):
        # 16 bits prime
        p, g, y = 28643, 1257, 3406
        verifier = UocZkpVerifier(p, g, y)
        verifier.c = 1811
        verifier.b = 1
        h = 10863
        r = verifier.verify(h)
        self.assertIsNotNone(r)
        self.assertFalse(r)

    def test_b0_5(self):
        # 16 bits prime
        p, g, y = 28643, 1257, 3406
        verifier = UocZkpVerifier(p, g, y)
        verifier.c = 22668
        verifier.b = 1
        h = 23236
        r = verifier.verify(h)
        self.assertIsNotNone(r)
        self.assertFalse(r)

    def test_b0_6(self):
        # 64 bits prime
        p, g, y = 7687815937255549241, 27, 828418027377238633
        verifier = UocZkpVerifier(p, g, y)
        verifier.c = 7682733136308746968
        verifier.b = 1
        h = 699336931761820991
        r = verifier.verify(h)
        self.assertIsNotNone(r)
        self.assertFalse(r)

    def test_b0_7(self):
        # 16 bits prime
        p, g, y = 28643, 1257, 3406
        verifier = UocZkpVerifier(p, g, y)
        verifier.c = 1811
        verifier.b = 0
        h = 10864
        r = verifier.verify(h)
        self.assertIsNotNone(r)
        self.assertFalse(r)

    def test_b0_8(self):
        # 16 bits prime
        p, g, y = 28643, 1257, 3406
        verifier = UocZkpVerifier(p, g, y)
        verifier.c = 22667
        verifier.b = 0
        h = 23236
        r = verifier.verify(h)
        self.assertIsNotNone(r)
        self.assertFalse(r)

    def test_b0_9(self):
        # 64 bits prime
        p, g, y = 7687815937255549241, 27, 828418027377238633
        verifier = UocZkpVerifier(p, g, y)
        verifier.c = 682733136308746968
        verifier.b = 0
        h = 699336931761820991
        r = verifier.verify(h)
        self.assertIsNotNone(r)
        self.assertFalse(r)

    def test_b1_1(self):
        # 16 bits prime
        p, g, y = 28643, 1257, 3406
        verifier = UocZkpVerifier(p, g, y)
        verifier.c = 2049
        verifier.b = 1
        h = 1574
        r = verifier.verify(h)
        self.assertTrue(r)

    def test_b1_2(self):
        # 16 bits prime
        p, g, y = 28643, 1257, 3406
        verifier = UocZkpVerifier(p, g, y)
        verifier.c = 17378
        verifier.b = 1
        h = 12062
        r = verifier.verify(h)
        self.assertTrue(r)

    def test_b1_3(self):
        # 64 bits prime
        p, g, y = 7687815937255549241, 27, 828418027377238633
        verifier = UocZkpVerifier(p, g, y)
        verifier.c = 4628254153313989938
        verifier.b = 1
        h = 2890501884662837007
        r = verifier.verify(h)
        self.assertTrue(r)

    def test_b1_4(self):
        # 16 bits prime
        p, g, y = 28643, 1257, 3406
        verifier = UocZkpVerifier(p, g, y)
        verifier.c = 2049
        verifier.b = 0
        h = 1574
        r = verifier.verify(h)
        self.assertIsNotNone(r)
        self.assertFalse(r)

    def test_b1_5(self):
        # 16 bits prime
        p, g, y = 28643, 1257, 3406
        verifier = UocZkpVerifier(p, g, y)
        verifier.c = 17378
        verifier.b = 0
        h = 12062
        r = verifier.verify(h)
        self.assertIsNotNone(r)
        self.assertFalse(r)

    def test_b1_6(self):
        # 64 bits prime
        p, g, y = 7687815937255549241, 27, 828418027377238633
        verifier = UocZkpVerifier(p, g, y)
        verifier.c = 4628254153313989938
        verifier.b = 0
        h = 2890501884662837007
        r = verifier.verify(h)
        self.assertIsNotNone(r)
        self.assertFalse(r)

    def test_b1_7(self):
        # 16 bits prime
        p, g, y = 28643, 1257, 3406
        verifier = UocZkpVerifier(p, g, y)
        verifier.c = 2048
        verifier.b = 1
        h = 1574
        r = verifier.verify(h)
        self.assertIsNotNone(r)
        self.assertFalse(r)

    def test_b1_8(self):
        # 16 bits prime
        p, g, y = 28643, 1257, 3406
        verifier = UocZkpVerifier(p, g, y)
        verifier.c = 17378
        verifier.b = 1
        h = 12064
        r = verifier.verify(h)
        self.assertIsNotNone(r)
        self.assertFalse(r)

    def test_b1_9(self):
        # 64 bits prime
        p, g, y = 7687815937255549241, 27, 828418027377238633
        verifier = UocZkpVerifier(p, g, y)
        verifier.c = 4628254153313989938
        verifier.b = 1
        h = 280501884662837007
        r = verifier.verify(h)
        self.assertIsNotNone(r)
        self.assertFalse(r)




class Test2_5_Challenge(unittest.TestCase):

    def test_challenge_ok_1(self):
        p, g, y, x = 28643, 1257, 3406, 28285
        prover = UocZkpProver(p, g, y, x)
        verifier = UocZkpVerifier(p, g, y)
        success, prob = challenge(prover, verifier, 1)
        self.assertTrue(success)
        self.assertEqual(prob, 0.5)

    def test_challenge_ok_2(self):
        p, g, y, x = 28643, 1257, 3406, 28285
        prover = UocZkpProver(p, g, y, x)
        verifier = UocZkpVerifier(p, g, y)
        success, prob = challenge(prover, verifier, 7)
        self.assertTrue(success)
        self.assertAlmostEqual(prob, 0.0078125, places=4)

    def test_challenge_ok_3(self):
        p, g, y, x = 7687815937255549241, 27, 828418027377238633, 6041213497581640253
        prover = UocZkpProver(p, g, y, x)
        verifier = UocZkpVerifier(p, g, y)
        success, prob = challenge(prover, verifier, 1)
        self.assertTrue(success)
        self.assertEqual(prob, 0.5)

    def test_challenge_ok_4(self):
        p, g, y, x = 7687815937255549241, 27, 828418027377238633, 6041213497581640253
        prover = UocZkpProver(p, g, y, x)
        verifier = UocZkpVerifier(p, g, y)
        success, prob = challenge(prover, verifier, 100)
        self.assertTrue(success)

    def test_challenge_error_1(self):
        p, g, y, x = 28643, 1257, 3406, 28285
        prover = UocZkpProver(p, g, y, x)
        verifier = UocZkpVerifier(p, g, y+1)
        success, prob = challenge(prover, verifier, 100)
        self.assertFalse(success)




class Test3_1_ZkpCheaterProverB0ComputeC(unittest.TestCase):

    def test_1(self):
        # 16 bits prime
        # Warning: this test assumes randint is used to chose r. If other methods
        # are used, the test may fail (and this does not necessarily mean compute_c
        # is not correctly implemented)
        seed(a=123456)
        p, g, y = 28643, 1257, 3406
        prover = UocZkpCheaterProverB0(p, g, y)
        c = prover.compute_c()

        # Python2
        # self.assertEqual(prover.r, 23075)
        # self.assertEqual(c, 928)
        self.assertEqual(prover.r, 26400)
        self.assertEqual(c, 24516)

    def test_2(self):
        # 64 bits prime
        # Warning: this test assumes randint is used to chose r. If other methods
        # are used, the test may fail (and this does not necessarily mean compute_c
        # is not correctly implemented)
        seed(a=654321)
        p, g, y = 7687815937255549241, 27, 828418027377238633
        prover = UocZkpCheaterProverB0(p, g, y)
        c = prover.compute_c()
        self.assertEqual(prover.r, 4372826025337746426)
        self.assertEqual(c, 2394546805488415621)




class Test3_2_ZkpCheaterProverB0ComputeH(unittest.TestCase):

    def test_b1_1(self):
        # 16 bits prime
        p, g, y = 28643, 1257, 3406
        prover = UocZkpCheaterProverB0(p, g, y)
        prover.r = 13067
        # The cheater can not pass the challenge...
        self.assertEqual(prover.compute_h(1), 13067)

    def test_b1_2(self):
        # 64 bits prime
        p, g, y = 7687815937255549241, 27, 828418027377238633
        prover = UocZkpCheaterProverB0(p, g, y)
        prover.r = 2873732016618999394
        # The cheater can not pass the challenge...
        self.assertEqual(prover.compute_h(1), 2873732016618999394)

    def test_b0_1(self):
        # 16 bits prime
        p, g, y = 28643, 1257, 3406
        prover = UocZkpCheaterProverB0(p, g, y)
        prover.r = 7224
        # The cheater passes the challenge!
        self.assertEqual(prover.compute_h(0), 7224)

    def test_b0_2(self):
        # 64 bits prime
        p, g, y = 7687815937255549241, 27, 828418027377238633
        prover = UocZkpCheaterProverB0(p, g, y)
        prover.r = 2077516426880017979
        # The cheater passes the challenge!
        self.assertEqual(prover.compute_h(0), 2077516426880017979)





class Test3_3_ZkpCheaterProverB1ComputeC(unittest.TestCase):

    def test_1(self):
        # 16 bits prime
        # Warning: this test assumes randint is used to chose r. If other methods
        # are used, the test may fail (and this does not necessarily mean compute_c
        # is not correctly implemented)
        seed(a=123456)
        p, g, y = 28643, 1257, 3406
        prover = UocZkpCheaterProverB1(p, g, y)

        self.assertEqual(prover.compute_c(), 17230)
        self.assertEqual(prover.r, 26400)

    def test_2(self):
        # 64 bits prime
        # Warning: this test assumes randint is used to chose r. If other methods
        # are used, the test may fail (and this does not necessarily mean compute_c
        # is not correctly implemented)
        seed(a=654321)
        p, g, y = 7687815937255549241, 27, 828418027377238633
        prover = UocZkpCheaterProverB1(p, g, y)
        self.assertEqual(prover.compute_c(), 2719766789085163149)
        self.assertEqual(prover.r, 4372826025337746426)





class Test3_4_ZkpCheaterProverB1ComputeH(unittest.TestCase):

    def test_b1_1(self):
        # 16 bits prime
        p, g, y = 28643, 1257, 3406
        prover = UocZkpCheaterProverB1(p, g, y)
        prover.r = 25002
        # The cheater passes the challenge!
        self.assertEqual(prover.compute_h(1), 25002)

    def test_b1_2(self):
        # 64 bits prime
        p, g, y = 7687815937255549241, 27, 828418027377238633
        prover = UocZkpCheaterProverB1(p, g, y)
        prover.r = 6802182025261317246
        # The cheater passes the challenge!
        self.assertEqual(prover.compute_h(1), 6802182025261317246)

    def test_b0_1(self):
        # 16 bits prime
        p, g, y = 28643, 1257, 3406
        prover = UocZkpCheaterProverB1(p, g, y)
        prover.r = 24044
        # The cheater can not pass the challenge...
        self.assertEqual(prover.compute_h(0), 24044)

    def test_b0_2(self):
        # 64 bits prime
        p, g, y = 7687815937255549241, 27, 828418027377238633
        prover = UocZkpCheaterProverB1(p, g, y)
        prover.r = 4442405816433452806
        # The cheater can not pass the challenge...
        self.assertEqual(prover.compute_h(0), 4442405816433452806)




if __name__ == '__main__':

    # create a suite with all tests

    # test_classes_to_run = [Test1_1_ElGamalKeyGen, Test1_2_ElGamalSign,
    #                        Test1_3_ElGamalVerify, Test1_4_ElGamalExtractPrivKey,
    #
    #                        Test2_1_0_ZkpProverInit, Test2_1_ZkpProverComputeC,
    #                        Test2_2_ZkpProverComputeH, Test2_3_0_kpVerifierInit,
    #                        Test2_3_ZkpVerifierChooseb, Test2_4_ZkpVerifierVerify,
    #                        Test2_5_Challenge,
    #
    #                        Test3_1_ZkpCheaterProverB0ComputeC, Test3_2_ZkpCheaterProverB0ComputeH,
    #                        Test3_3_ZkpCheaterProverB1ComputeC, Test3_4_ZkpCheaterProverB1ComputeH]
    test_classes_to_run = [Test1_1_ElGamalKeyGen, Test1_2_ElGamalSign,
                           Test1_3_ElGamalVerify, Test1_4_ElGamalExtractPrivKey,

                           Test2_1_0_ZkpProverInit, Test2_1_ZkpProverComputeC,
                           Test2_2_ZkpProverComputeH, Test2_3_0_kpVerifierInit,
                           Test2_3_ZkpVerifierChooseb, Test2_4_ZkpVerifierVerify,
                           Test2_5_Challenge,

                           Test3_1_ZkpCheaterProverB0ComputeC]

    loader = unittest.TestLoader()
    suites_list = []
    for test_class in test_classes_to_run:
        suite = loader.loadTestsFromTestCase(test_class)
        suites_list.append(suite)

    all_tests_suite = unittest.TestSuite(suites_list)

    # run the test suite with high verbosity
    runner = unittest.TextTestRunner(verbosity=2)
    results = runner.run(all_tests_suite)


