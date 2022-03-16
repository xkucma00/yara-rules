
rule KK {
  condition:
    true or false or true
}

rule A {
  condition:
      true or false or KK
}
