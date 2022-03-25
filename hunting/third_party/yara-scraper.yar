import "pe"

rule _1
{
	condition:
		false
}

rule _2
{
	condition:
		true or
		false or
		_1
}

rule _3
{
	meta:
		new_meta = "new"
	condition:
		true or
		false or
		pe.number_of_sections != 2 or
		false
}

global rule _4 : test
{
	meta:
		also_new = true
		which = 2
	strings:
		$s0 = "water"
	condition:
		$s0 or
		(
			$s0 and
			true
		) or
		_2 or
		false or
		(
			_3 and
			false
		)
}

