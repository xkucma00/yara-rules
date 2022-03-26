
rule KK {
  condition:
    false
}

rule A {
  condition:
      true or false or KK
}
