#pragma once
#include "utils/macros.h"
#include "utils/BitSet.h"
#include "enchantum/bitwise_operators.hpp"
#include <cstdint>
#include <string>
#include <type_traits>
#include "debug.h"

enum class ResolverFlags : uint32_t
{
  None                 = 0,
  NoFilter             = 1 << 0,  // "no filter", "non-filtering", "unfiltered"
  NoLog                = 1 << 1,  // "no logs", "non-logging", "zero logs"
  NoPersistentLogs     = 1 << 2,  // "No persistent logs"
  DNSSEC               = 1 << 3,  // "dnssec", "supports dnssec"
  Do53                 = 1 << 4,  // Plain DNS server.
  DNSCrypt             = 1 << 5,  // "dnscrypt"
  DoH                  = 1 << 6,  // DoH, "DNS-over-HTTPS"
  DoT                  = 1 << 7,  // DoT, "DNS-over-TLS"
  DoQ                  = 1 << 8,  // DoQ - DNS-over-QUIC
  oDoHRelay            = 1 << 9,  // oDoH relay
  oDoHTarget           = 1 << 10,  // oDoH target
  DNSCryptRelay        = 1 << 11, // DNSCrypt relay
  IPv4                 = 1 << 12, // "ipv4"
  IPv6                 = 1 << 13, // "ipv6"
  NoECS                = 1 << 14, // "no ecs", "no edns client-subnet"
  IncompatibleWithAnon = 1 << 15, // "incompatible with dns anonymization", "incompatible with anonymization"
  GFWFiltering         = 1 << 16, // "gfw filtering", "gfw poisoning"
  HTTP3                = 1 << 17, // "http/3", "doh3"
  QNAMEMinimization    = 1 << 18, // "qname minimization"
  MalwareBlocking      = 1 << 19, // "malware blocking", "malicious domains", "phishing"
  AdBlocking           = 1 << 20, // "adblock", "blocks ads", "ad-filtering"
  TrackingBlocking     = 1 << 21, // "blocks trackers"
  SocialMediaBlocking  = 1 << 22, // "blocks social media"
  FamilyFilter         = 1 << 23, // "adult content blocking", "family safety", "parental control"
  Anycast              = 1 << 24, // "anycast"
  NoPadding            = 1 << 25, // "no padding" - it is very unclear if servers not mentioning padding DO have padding however.
};

ENCHANTUM_DEFINE_BITWISE_FOR(ResolverFlags)

constexpr ResolverFlags protocols = ResolverFlags::Do53 | ResolverFlags::DNSCrypt | ResolverFlags::DoH | ResolverFlags::DoT | ResolverFlags::DoQ |
  ResolverFlags::oDoHRelay | ResolverFlags::oDoHTarget | ResolverFlags::DNSCryptRelay;

std::string print_flags(ResolverFlags flags);
