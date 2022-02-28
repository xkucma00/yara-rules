include "../test1.yar"
import "pe"

rule B {
  condition:
    true or false or pe.number_of_sections == 2
}

rule ahoj : test {
  strings:
    $s0 = "water"
  condition:
    $s0 or ($s0 and true) or A or false
}
