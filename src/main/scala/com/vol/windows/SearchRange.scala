package com.bbs.vol.utils

import java.net.InetAddress

import com.google.common.net.InetAddresses

import scala.util.Try

trait SearchRange {

  /** Putting this off until I need it */
  private[vol] def seachIpRange(value: String, start: String, end: String): Boolean = {
    if(ipToLong(start) to ipToLong(end) contains ipToLong(value)) true
    else false

  } // END ipRange()

  /** Convert IP address to Long */
  private[vol] def ipToLong(ip: String): Long = {
    
    /** Uses Google's Guava library to avoid DNS lookup costs */
    val addr: InetAddress = InetAddresses.forString(ip)
    // val addr = InetAddress.getByName(ip)
    val ipAddr: Array[Byte] = addr.getAddress
    var result: Long = 0L
    for(value <- ipAddr){
      result <<= 8
      result |= value & 0xff
    }
    return result
  } // END getLong

  private[vol] def searchHexRange(value: String, start: String, end: String): Boolean = {
    val bool = searchRange(hex2Long(value), hex2Long(start), hex2Long(end))

    return bool
  } // END hexRange()
  private[vol] def searchHexRange(value: String, start: Long, end: Long): Boolean = {
    val bool = start to end contains hex2Long(value)
    return bool
  }
  private[vol] def searchHexRange(value: Long, start: Long, end: Long): Boolean = {

    val bool = searchRange(value, start, end)

  return bool
  }
  private[vol] def searchHexRange(value: Long, start: String, end: String): Boolean = {

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
