// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.util.Map;
import java.util.HashMap;
import java.io.IOException;

/**
 * The Name Server Identifier Option
 *
 * @see OPTRecord
 * @author Brian Wellington
 * @author Oli Schacher
 * @see <a href="https://tools.ietf.org/html/rfc8914">RFC 8914: Extended DNS Errors (EDE)
 *     Option</a>
 */
public class EDEOption extends EDNSOption {

  public enum ExtendedErrorCode {
    Other(0,"Other"),
    UnsupportedDNSKEYAlgorithm(1,"Unsupported DNSKEY Algorithm"),
    UnsupportedDSDigestType(2,"Unsupported DS Digest Type"),
    StaleAnswer(3,"Stale Answer"),
    ForgedAnswer(4,"Forged Answer"),
    DNSSECIndeterminate(5,"DNSSEC Indeterminate"),
    DNSBogus(6,"DNSSEC Bogus"),
    SignatureExpired(7,"Signature Expired"),
    SignatureNotYetValid(8,"Signature Not Yet Valid"),
    DNSKEYMissing(9,"DNSKEY Missing"),
    RRSIGsMissing(10,"RRSIGs Missing"),
    NoZoneKeyBitSet(11,"No Zone Key Bit Set"),
    NSECMissing(12,"NSEC Missing"),
    CachedError(13,"Cached Error"),
    NotReady(14,"Not Ready"),
    Blocked(15,"Blocked"),
    Censored(16,"Censored"),
    Filtered(17,"Filtered"),
    Prohibited(18,"Prohibited"),
    StaleNXDOMAINAnswer(19,"Stale NXDOMAIN Answer"),
    NotAuthoritative(20,"Not Authoritative"),
    NotSupported(21,"Not Supported"),
    NoReachableAuthority(22,"No Reachable Authority"),
    NetworkError(23,"Network Error"),
    InvalidData(24,"Invalid Data");

    private static final Map<Integer, ExtendedErrorCode> BY_CODE = new HashMap<>();
    static {
        for (ExtendedErrorCode e : values()) {
            BY_CODE.put(e.code, e);
        }
    }

    public final int code;
    public final String description;

    private ExtendedErrorCode(int code, String description){
      this.code = code; 
      this.description = description;
    }

    public static ExtendedErrorCode valueOfCode(int code){
      return BY_CODE.get(code);
    }

  }

  private ExtendedErrorCode code = ExtendedErrorCode.Other;
  private String extraText = "";

  EDEOption() {
    super(EDNSOption.Code.EDE);
  }

  /**
   * Construct an EDE option.
   *
   */
  public EDEOption(ExtendedErrorCode code) {
    this(code,"");
  }

  public EDEOption(ExtendedErrorCode code, String extraText){
    super(EDNSOption.Code.EDE);
    this.code = code;
    this.extraText = extraText;
  }


  @Override
  void optionFromWire(DNSInput in) throws IOException {

   this.code = ExtendedErrorCode.valueOfCode(in.readU16());
   try {
    this.extraText = new String(in.readByteArray(), "UTF-8");
   } catch (java.io.UnsupportedEncodingException e){
     throw new WireParseException("EDE EXTRA-TEXT could not be parsed into UTF-8 String");
   }
  }

  @Override
  void optionToWire(DNSOutput out) {
    out.writeU16(this.code.code);
    if(extraText.length() > 0){
      try{
        out.writeByteArray(this.extraText.getBytes("UTF-8"));
      } catch (java.io.UnsupportedEncodingException e){
        throw new IllegalArgumentException("EDE EXTRA-TEXT String can not be UTF-8 encoded");
      }
    }
  }

  @Override
  String optionToString() {
    return code.code+"("+code.description+")"+"("+extraText+")";
  }
}
