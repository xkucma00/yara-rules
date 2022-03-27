import "pe"

rule KK__33__40
{
	meta:
		__oldest_ancestor_id = false
		__predecessor_id = false
		__id = 33
		__source_id = 4
		__original_path = "test1.yar"
		__original_name = "KK"
		__rule_type = "TODO"
		__hunting_tag = "TODO"
		__description = "TODO"
		__tool = "TODO 0.1.0"
		__author = "https://github.com/xkucma00/yara-rules.git"
		oldest_ancestor_id = false
		predecessor_id = false
		id = 40
		source_id = 4
		original_path = "hunting/third_party/yara-scraper.yar"
		original_name = "KK__33"
		rule_type = "TODO"
		hunting_tag = "TODO"
		description = "TODO"
		tool = "TODO 0.1.0"
		author = "https://github.com/xkucma00/yara-rules.git"
	condition:
		false
}

rule A__34__41
{
	meta:
		__oldest_ancestor_id = false
		__predecessor_id = false
		__id = 34
		__source_id = 4
		__original_path = "test1.yar"
		__original_name = "A"
		__rule_type = "TODO"
		__hunting_tag = "TODO"
		__description = "TODO"
		__tool = "TODO 0.1.0"
		__author = "https://github.com/xkucma00/yara-rules.git"
		oldest_ancestor_id = false
		predecessor_id = false
		id = 41
		source_id = 4
		original_path = "hunting/third_party/yara-scraper.yar"
		original_name = "A__34"
		rule_type = "TODO"
		hunting_tag = "TODO"
		description = "TODO"
		tool = "TODO 0.1.0"
		author = "https://github.com/xkucma00/yara-rules.git"
	condition:
		true or
		false or
		KK__33__40
}

rule B__35__42
{
	meta:
		__oldest_ancestor_id = false
		__predecessor_id = false
		__id = 35
		__source_id = 4
		__original_path = "test2/tesst.yar"
		__original_name = "B"
		__rule_type = "TODO"
		__hunting_tag = "TODO"
		__description = "TODO"
		__tool = "TODO 0.1.0"
		__author = "https://github.com/xkucma00/yara-rules.git"
		____new_meta = "new"
		oldest_ancestor_id = false
		predecessor_id = false
		id = 42
		source_id = 4
		original_path = "hunting/third_party/yara-scraper.yar"
		original_name = "B__35"
		rule_type = "TODO"
		hunting_tag = "TODO"
		description = "TODO"
		tool = "TODO 0.1.0"
		author = "https://github.com/xkucma00/yara-rules.git"
	condition:
		true or
		false or
		pe.number_of_sections != 2 or
		false
}

rule KK__33
{
	meta:
		oldest_ancestor_id = false
		predecessor_id = false
		id = 33
		source_id = 4
		original_path = "test1.yar"
		original_name = "KK"
		rule_type = "TODO"
		hunting_tag = "TODO"
		description = "TODO"
		tool = "TODO 0.1.0"
		author = "https://github.com/xkucma00/yara-rules.git"
	condition:
		false
}

rule A__39
{
	meta:
		oldest_ancestor_id = 34
		predecessor_id = 37
		id = 39
		source_id = 4
		original_path = "test1.yar"
		original_name = "A"
		rule_type = "TODO"
		hunting_tag = "TODO"
		description = "TODO"
		tool = "TODO 0.1.0"
		author = "https://github.com/xkucma00/yara-rules.git"
	condition:
		true or
		false or
		KK__33
}

rule B__35
{
	meta:
		__new_meta = "new"
		oldest_ancestor_id = false
		predecessor_id = false
		id = 35
		source_id = 4
		original_path = "test2/tesst.yar"
		original_name = "B"
		rule_type = "TODO"
		hunting_tag = "TODO"
		description = "TODO"
		tool = "TODO 0.1.0"
		author = "https://github.com/xkucma00/yara-rules.git"
	condition:
		true or
		false or
		pe.number_of_sections != 2 or
		false
}

global rule ahoj__44 : test
{
	meta:
		__which = 2
		__also_new = true
		oldest_ancestor_id = 36
		predecessor_id = 38
		id = 44
		source_id = 4
		original_path = "test2/tesst.yar"
		original_name = "ahoj"
		rule_type = "TODO"
		hunting_tag = "TODO"
		description = "TODO"
		tool = "TODO 0.1.0"
		author = "https://github.com/xkucma00/yara-rules.git"
	strings:
		$s0 = "water"
	condition:
		$s0 or
		(
			$s0 and
			true
		) or
		A__39 or
		false or
		(
			B__35 and
			false
		)
}

global rule ahoj__36__43 : test
{
	meta:
		__oldest_ancestor_id = false
		__predecessor_id = false
		__id = 36
		__source_id = 4
		__original_path = "test2/tesst.yar"
		__original_name = "ahoj"
		__rule_type = "TODO"
		__hunting_tag = "TODO"
		__description = "TODO"
		__tool = "TODO 0.1.0"
		__author = "https://github.com/xkucma00/yara-rules.git"
		____which = 2
		____also_new = true
		oldest_ancestor_id = false
		predecessor_id = false
		id = 43
		source_id = 4
		original_path = "hunting/third_party/yara-scraper.yar"
		original_name = "ahoj__36"
		rule_type = "TODO"
		hunting_tag = "TODO"
		description = "TODO"
		tool = "TODO 0.1.0"
		author = "https://github.com/xkucma00/yara-rules.git"
	strings:
		$s0 = "water"
	condition:
		$s0 or
		(
			$s0 and
			true
		) or
		A__34__41 or
		false or
		(
			B__35__42 and
			false
		)
}

