package com.bbs.vol.utils

trait SearchRange {

  /** Putting this off until I need it */
  private[com] def searchIpRange(value: String, start: String, end: String): Boolean = {
    if(ipToLong(start) to ipToLong(end) contains ipToLong(value)) true
    else false

  } // END ipRange()

  /** Convert IP address to Long */
  private[com] def ipToLong(ip: String): Long = {

    /** */
    val splitIp = ip.split('.')
    val octet1 = splitIp(0).toLong * 16777216 //cubed
    val octet2 = splitIp(1).toLong * 65536
    val octet3 = splitIp(2).toLong * 256
    val octet4 = splitIp(3).toLong

    val longValue = octet1 + octet2 + octet3 + octet4

    return longValue
  } // END getLong

  private[com] def searchHexRange(value: String, start: String, end: String): Boolean = {
    val bool = searchRange(hex2Long(value), hex2Long(start), hex2Long(end))

    return bool
  } // END hexRange()
  private[com] def searchHexRange(value: String, start: Long, end: Long): Boolean = {
    val bool = start to end contains hex2Long(value)
    return bool
  }
  private[com] def searchHexRange(value: Long, start: Long, end: Long): Boolean = {

    val bool = searchRange(value, start, end)

    return bool
  }
  private[com] def searchHexRange(value: Long, start: String, end: String): Boolean = {

    val bool = searchRange(value, hex2Long(start), hex2Long(end))

    return bool
  }

  private[this] def searchRange(value: Long, start: Long, end: Long) = {
    if (start to end contains value) true
    else false
  } // END

  /** convert hex memory location to an integer. */
  private[this] def hex2Long(hex: String): Long = {
    val bigInt = Integer.parseInt(hex.drop(2), 16)
    bigInt.longValue()
    // hex.toList.map("0123456789abcdef".indexOf(_)).reduceLeft(_ * 16 + _)
  } // END hex2Long

} // END SearchRange trait
