#!/usr/bin/env python
# -*- coding: utf-8 -*-
import random

from sympy.ntheory.residue_ntheory import is_primitive_root
from sympy.ntheory.primetest import isprime
from sympy import prime

# Log level constants
LOG_CRITICAL = 0
LOG_INFO = 1
LOG_DEBUG = 2

# Current log level
LOG_LEVEL = LOG_CRITICAL


class InvalidParams(Exception):
    """
    Exception raised when the initialization params are not valid
    """
    pass


def print_debug(msg, log_level):
    """
    Prints a message if log_level <= LOG_LEVEL
    :param msg: string, the message to print
    :param log_level: int, message's level
    """
    if log_level <= LOG_LEVEL:
        print(msg)


# --- IMPLEMENTATION GOES HERE ---------------------------------------------
#  Student helpers (functions, constants, etc.) can be defined here, if needed


# --------------------------------------------------------------------------


def uoc_elgamal_keygen(n_bits):
    """
    EXERCISE 1.1: Implements ElGamal key generation algorithm. Generates a
    random ElGamal key pair with prime p of length n_bits.

    :param n_bits: int, length in bits of the prime p
    :return: two element tuple with private and public keys.
             The private key is a list of three values: the prime p, the
             generator alpha, and the secret value d.
             The public key is a list of three values: the prime p, the
             generator alpha, and public value beta (alpha^d).
    """

    k_priv = (None, None, None)
    k_pub = (None, None, None)

    # --- IMPLEMENTATION GOES HERE ---

    p = prime(n_bits)
    alpha = random.randrange(1,p)
    d = random.randrange(2,p-1)
    beta = pow(alpha,d,p)

    k_priv = (p, alpha, d)
    k_pub = (p, alpha, beta)


    # --------------------------------

    return k_priv, k_pub


def uoc_elgamal_sign(k_priv, m, h=None):
    """
    EXERCISE 1.2: Implements ElGamal signature generation algorithm.

    :param k_priv: 3-element tuple with the private key (as returned by
                   uoc_elgamal_keygen).
    :param m: int, message to sign
    :param h: Optional int, the random h value (if present, the function
              must use the supplied h value, otherwise, it must select
              h randomly.
    :return: two element tuple with the signature ([r, s])
    """
    r, s = None, None

    # --- IMPLEMENTATION GOES HERE ---
    (p, alpha, d) = k_priv

    if h == None:
        while (h == None):
            new_h = random.randrange(2, p - 2)
            if math.gcd(new_h, p - 1) == 1:
                h = new_h

    r = pow(alpha, h, p)

    p1 = p - 1
    dr = (d * r) % p1
    mdr = (m - dr) % p1
    s = (mdr * pow(h, -1, p1)) % p1
    # --------------------------------

    return r, s


def uoc_elgamal_verify(sig, k_pub, m):
    """
    EXERCISE 1.3: Implements ElGamal signature verification algorithm.

    :param sig: two value tuple with the signature to verify (as returned
                by uoc_elgamal_sign)
    :param k_pub: 3-element tuple with the public key (as returned by
                  uoc_elgamal_keygen).
    :param m: int, message that was signed
    :return: boolean, True iff signature is valid
    """

    result = None

    # --- IMPLEMENTATION GOES HERE ---

    # --------------------------------

    return result


def uoc_elgamal_extract_private_key(k_pub, m1, sig1, m2, sig2):
    """
    EXERCISE 1.4: Implements the algorithm used by an attacker to recover
    the private key from two signatures.

    :param k_pub: 3-element tuple with the public key (as returned by
                  uoc_elgamal_keygen).
    :param m1: int, a message that was signed
    :param sig1: signature of message m1 (as returned by uoc_elgamal_sign)
    :param m2: int, a message that was signed
    :param sig2: signature of message m2 (as returned by uoc_elgamal_sign)
    :return: a 3-element tuple with the private key if it was possible to
             recover it, -1 otherwise
    """

    k_priv = None

    # --- IMPLEMENTATION GOES HERE ---

    # --------------------------------

    return k_priv


class UocZkpProver:
    """
    Class representing a honest prover. The prover knowns a value x such that
    g^x = y mod p, and wants to prove this knowledge without revealing x.
    """

    def __init__(self, p, g, y, x, name="HonestProver"):
        """
        Initializes the prover. Checks the validity of the arguments, sets the
        public parameters p, g, y and sets the secret x.

        This method has to initialize instance variables p, g, y and x (r will
        remain unset until compute_c method is called).

        :param p: integer, modulus
        :param g: integer, base
        :param y: integer, g^x mod p
        :param x: integer, secret
        :param name: optional string, name of the prover (to be used when
                     printing data to the console)
        """

        self.p = None
        self.g = None
        self.y = None
        self.x = None
        self.r = None
        self.name = name

        try:
            assert (isprime(p))
            assert (y < p)
            assert (is_primitive_root(g, p))
            if x is not None:
                assert (pow(g, x, p) == y)
        except:
            raise InvalidParams

        self.p = p
        self.g = g
        self.y = y
        self.x = x

        print_debug("{}:\tInitialized with p = {}, g = {}, y = {} and x = {}".format(
            self.name, self.p, self.g, self.y, self.x), LOG_INFO)

    def compute_c(self):
        """
        EXERCISE 2.1: Chooses a random r and computes c.

        This method must set self.r.
        :return: integer, c
        """

        c = None

        # --- IMPLEMENTATION GOES HERE ---

        # --------------------------------

        print_debug("{}:\tI amb sending c = {}".format(self.name, c), LOG_INFO)
        return c

    def compute_h(self, b):
        """
        EXERCISE 2.2: Computes h for the given b.
        :param b: integer with a boolean value (0 or 1)
        :return: integer, h
        """

        h = None

        # --- IMPLEMENTATION GOES HERE ---

        # --------------------------------

        print_debug("{}:\tI amb sending h = {}".format(self.name, h), LOG_INFO)
        return h


class UocZkpVerifier:
    """
    Class representing a verifier. The verifier wants to known whether the

    prover has a value x such that g^x = y mod p.
    """

    def __init__(self, p, g, y, name="Verifier"):
        """
        Initializes the verifier. Checks the validity of the arguments, and
        sets the public parameters p, g, y.

        This method has to initialize instance variables p, g and y (c and
        b will remain unset until choose_b method is called).

        :param p: integer, modulus
        :param g: integer, base
        :param y: integer, g^x mod p
        :param name: optional string, name of the verifier (to be used when
                     printing data to the console)
        """
        self.p = None
        self.g = None
        self.y = None
        self.c = None
        self.b = None
        self.name = name

        try:
            assert (isprime(p))
            assert (y < p)
            assert (is_primitive_root(g, p))

        except:
            raise InvalidParams

        self.p = p
        self.g = g
        self.y = y

        print_debug("{}:\t\tInitialized with p = {}, g = {} and y = {}"
                    .format(self.name, self.p, self.g, self.y), LOG_INFO)

    def choose_b(self, c):
        """
        EXERCISE 2.3: Selects a random boolean b value.

        This method has to initialize instance variables b and c.
        :param c: integer, value c (received from the prover)
        :return: integer, b with the chosen boolean
        """

        # --- IMPLEMENTATION GOES HERE ---

        # --------------------------------

        print_debug("{}:\t\tI have chosen b = {}"
                    .format(self.name, self.b), LOG_INFO)
        return self.b

    def verify(self, h):
        """
        EXERCISE 2.4: Verifies if the prover has correctly solved the challenge.

        :param h: integer, value h (received from the proves)
        :return: boolean, result of the proof
        """

        result = None

        # --- IMPLEMENTATION GOES HERE ---

        # --------------------------------

        print_debug("{}:\t\tThe result of the verification is {}"
                    .format(self.name, result), LOG_INFO)
        return result


def challenge(prover, verifier, num_times=1):
    """
    EXERCISE 2.5: Executes the full zero knowledge protocol between a
    prover and a verifier num_times times. The execution of the protocol
    is successful if the prover is able to convice the verifier in all
    the executions.

    :param prover: UocZkpProver object
    :param verifier: UocZkpVerifier object
    :param num_times: integer, number of times to execute the ZKP
    :return: 2-element tuple, a boolean indicating whether the challenge was
             successful and a float
    """

    success, prob = None, None

    # --- IMPLEMENTATION GOES HERE ---

    # --------------------------------

    return success, prob


class UocZkpCheaterProverB0(UocZkpProver):
    """
    Class representing a dishonest prover. The prover does not know a value x
    such that g^x = y mod p, and wants to try to convince the verifier
    otherwise. This dishonest prover will try to do so by assuming the
    verifier always chooses b=0.
    """

    def __init__(self, p, g, y, name="CheaterProv0"):
        """
        Initializes the prover. We can use the initialization method of the
        parent class UocZkpProver, but since the dishonest proves does not
        know x, this parameter will now be None.
        :param p: integer, modulus
        :param g: integer, base
        :param y: integer, g^x mod p
        :param name: optional string, name of the prover (to be used when
                     printing data to the console)
        """

        UocZkpProver.__init__(self, p, g, y, None, name=name)

    def compute_c(self):
        """
        EXERCISE 3.1: Chooses a random r and computes c.

        This method must set self.r.
        :return: integer, c
        """

        c = None

        # --- IMPLEMENTATION GOES HERE ---

        # --------------------------------

        print_debug("{}:\tI amb sending c = {}".format(self.name, c), LOG_INFO)
        return c

    def compute_h(self, b):
        """
        EXERCISE 3.2: Overwrites the computation of h, assuming b is equal
        to 0 (if b != 0, then the prover will not be able to convince the
        verifier)

        :param b: integer with a boolean value (0 or 1)
        :return: integer, h
        """

        h = None

        # --- IMPLEMENTATION GOES HERE ---

        # --------------------------------

        print_debug("{}:\tI amb sending h = {}".format(self.name, h), LOG_INFO)
        return h


class UocZkpCheaterProverB1(UocZkpProver):
    """
    Class representing a dishonest prover. The prover does not knoe a value x
    such that g^x = y mod p, and wants to try to convince the verifier otherwise.
    This dishonest prover will try to do so by assuming the verifier always
    chooses b=1.
    """

    def __init__(self, p, g, y):
        """
        Initializes the prover. We can use the initialization method of the
        parent class UocZkpProver, but since the dishonest proves does not
        know x, this parameter will now be None.

        :param p: integer, modulus
        :param g: integer, base
        :param y: integer, g^x mod p
        """

        UocZkpProver.__init__(self, p, g, y, None, name="CheaterProv1")

    def compute_c(self):
        """
        EXERCISE 3.3: Chooses a random r and computes c' (assuming b will be
        equal to 1).

        This method must set self.r.
        :return: integer, c
        """

        c = None

        # --- IMPLEMENTATION GOES HERE ---

        # --------------------------------

        print_debug("{}:\tI amb sending c = {}".format(self.name, c), LOG_INFO)
        return c

    def compute_h(self, b):
        """
        EXERCISE 3.4: Overwrites the computation of h, assuming b is equal to
        1 (if b != 1, then the prover will not be able to convice the verifier)

        :param b: integer with a boolean value (0 or 1)
        :return: integer, h
        """

        h = None

        # --- IMPLEMENTATION GOES HERE ---

        # --------------------------------

        print_debug("{}:\tI amb sending h = {}".format(self.name, h), LOG_INFO)
        return h



