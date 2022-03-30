include "../test1.yar"
import "pe"

rule B {
  meta:
    new_meta = "new"
  condition:
    true or false or pe.number_of_sections != 2
}

global
private rule ahoj : test {
  meta: 
    also_new = true
    which = 2
  strings:
    $s0 = "water"
  condition:
    $s0 or ($s0 and true) or A or false or (B and false)
}
