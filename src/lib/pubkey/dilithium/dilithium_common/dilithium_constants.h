/*
 * Crystals Dilithium Constants
 *
 * (C) 2022-2023 Jack Lloyd
 * (C) 2022      Manuel Glaser - Rohde & Schwarz Cybersecurity
 * (C) 2022-2023 Michael Boric, René Meusel - Rohde & Schwarz Cybersecurity
 * (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_DILITHIUM_CONSTANTS_H_
#define BOTAN_DILITHIUM_CONSTANTS_H_

#include <botan/dilithium.h>

namespace Botan {

class Dilithium_Symmetric_Primitives;

/**
 * Algorithm constants and parameter-set dependent values
 */
class DilithiumConstants final {
   public:
      /// base data type for most calculations
      using T = int32_t;

      /// number of coefficients in a polynomial
      static constexpr T N = 256;

      /// modulus
      static constexpr T Q = 8380417;

      /// number of dropped bits from t (see FIPS 204 Section 5)
      static constexpr T D = 13;

      /// as specified in FIPS 204 (see Algorithm 36 (NTT^-1), f = 256^-1 mod Q)
      static constexpr T F = 8347681;

      /// the 512-th root of unity modulo Q (see FIPS 204 Section 8.5)
      static constexpr T ROOT_OF_UNITY = 1753;

      /// degree of the NTT polynomials
      static constexpr size_t NTT_Degree = 256;

   public:
      /// \name Byte length's of various hash outputs and seeds
      /// @{

      static constexpr size_t SEED_RANDOMNESS_BYTES = 32;
      static constexpr size_t SEED_RHO_BYTES = 32;
      static constexpr size_t SEED_RHOPRIME_BYTES = 64;
      static constexpr size_t SEED_SIGNING_KEY_BYTES = 32;
      static constexpr size_t MESSAGE_HASH_BYTES = 64;
      static constexpr size_t PUBLIC_KEY_HASH_BYTES = 32;
      static constexpr size_t COMMITMENT_HASH_FULL_BYTES = 32;
      static constexpr size_t COMMITMENT_HASH_C1_BYTES = 32;

      /// @}

   public:
      enum DilithiumTau : uint32_t { _39 = 39, _49 = 49, _60 = 60 };

      enum DilithiumLambda : uint32_t { _128 = 128, _192 = 192, _256 = 256 };

      enum DilithiumGamma1 : uint32_t { ToThe17th = (1 << 17), ToThe19th = (1 << 19) };

      enum DilithiumGamma2 : uint32_t { Qminus1DevidedBy88 = (Q - 1) / 88, Qminus1DevidedBy32 = (Q - 1) / 32 };

      enum DilithiumEta : uint32_t { _2 = 2, _4 = 4 };

      enum DilithiumBeta : uint32_t { _78 = 78, _196 = 196, _120 = 120 };

      enum DilithiumOmega : uint32_t { _80 = 80, _55 = 55, _75 = 75 };

      DilithiumConstants(DilithiumMode dimension);
      ~DilithiumConstants() = default;

      DilithiumConstants(const DilithiumConstants& other) : DilithiumConstants(other.m_mode) {}

      DilithiumConstants(DilithiumConstants&& other) = default;
      DilithiumConstants& operator=(const DilithiumConstants& other) = delete;
      DilithiumConstants& operator=(DilithiumConstants&& other) = default;

      bool is_modern() const { return m_mode.is_modern(); }

      bool is_aes() const { return m_mode.is_aes(); }

   public:
      /// \name Foundational constants
      /// @{

      /// hamming weight of the polynomial 'c' sampled from the commitment's hash
      DilithiumTau tau() const { return m_tau; }

      /// collision strength of the commitment hash function
      DilithiumLambda lambda() const { return m_lambda; }

      /// coefficient range of the randomly sampled mask 'y'
      DilithiumGamma1 gamma1() const { return m_gamma1; }

      /// low-order rounding range for decomposing the commitment from polynomial vector 'w'
      DilithiumGamma2 gamma2() const { return m_gamma2; }

      /// dimensions of the expanded matrix A
      uint8_t k() const { return m_k; }

      /// dimensions of the expanded matrix A
      uint8_t l() const { return m_l; }

      /// coefficient range of the private key's polynomial vectors 's1' and 's2'
      DilithiumEta eta() const { return m_eta; }

      /// tau * eta
      DilithiumBeta beta() const { return m_beta; }

      /// maximal hamming weight of the hint polynomial vector 'h'
      DilithiumOmega omega() const { return m_omega; }

      /// length of the entire commitment hash in bytes
      size_t commitment_hash_full_bytes() const { return COMMITMENT_HASH_FULL_BYTES; }

      /// @}

      /// \name Sizes of encoded data structures
      /// @{

      /// byte length of the encoded signature
      size_t signature_bytes() const { return m_signature_bytes; }

      /// byte length of the encoded public key
      size_t public_key_bytes() const { return m_public_key_bytes; }

      /// byte length of the encoded private key
      size_t private_key_bytes() const { return m_private_key_bytes; }

      /// byte length of the packed commitment polynomial vector 'w1'
      size_t serialized_commitment_bytes() const { return m_serialized_commitment_bytes; }

      /// @}

      DilithiumMode mode() const { return m_mode; }

      Dilithium_Symmetric_Primitives& symmetric_primitives() const { return *m_symmetric_primitives; }

   private:
      DilithiumMode m_mode;

      DilithiumTau m_tau;
      DilithiumLambda m_lambda;
      DilithiumGamma1 m_gamma1;
      DilithiumGamma2 m_gamma2;
      uint8_t m_k;
      uint8_t m_l;
      DilithiumEta m_eta;
      DilithiumBeta m_beta;
      DilithiumOmega m_omega;

      uint32_t m_private_key_bytes;
      uint32_t m_public_key_bytes;
      uint32_t m_signature_bytes;
      uint32_t m_serialized_commitment_bytes;

      // Mode dependent primitives
      std::unique_ptr<Dilithium_Symmetric_Primitives> m_symmetric_primitives;
};

}  // namespace Botan

#endif
