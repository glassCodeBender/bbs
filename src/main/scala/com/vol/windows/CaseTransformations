package com.bbs.vol.utils

/**
  * An Interface for common transformations on case classes
  */
trait CaseTransformations {

  /**
    * Thanks github guy for this code! Awesome code!
    *
    * Filter to only include case classes w/ distinct values and maintain order of collection.
    * Example:
    * vec = Vector(ProcessBbs(name = "value", "what", "ever"), ProcessBby(name = "value", "what", "not"), ProcessBbs(name = "foo", "bar", "cool"))
    * filterByDistinctP(vec)(_.name)
    *
    * Output: Vector(ProcessBbs(name = "value", "what", "ever"), ProcessBbs(name = "foo", "bar", "cool"))
    */
  private[vol] def distinctBy[V,E](vec: Seq[V])(f: V => E) = {
    vec.foldLeft((Vector.empty[V], Set.empty[E])) {
      case ((acc, set), item) =>
        val key = f(item)
        if (set.contains(key)) (acc, set)
        else (acc :+ item, set + key)
    }._1
  } // END distinctBy()

} // END CaseTransformations
