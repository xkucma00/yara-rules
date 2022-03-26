
rule KK {
  condition:
    false
}

rule A {
  condition:
      false or KK
}
