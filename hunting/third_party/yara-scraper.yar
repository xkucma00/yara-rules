import "pe"

rule KK__33
{
	meta:
		author = "https://github.com/xkucma00/yara-rules.git"
		tool = "TODO 0.1.0"
		description = "TODO"
		hunting_tag = "TODO"
		rule_type = "TODO"
		original_name = "KK"
		original_path = "test1.yar"
		source_id = 4
		id = 33
		predecessor_id = false
		oldest_ancestor_id = false
	condition:
		false
}

rule A__39
{
	meta:
		author = "https://github.com/xkucma00/yara-rules.git"
		tool = "TODO 0.1.0"
		description = "TODO"
		hunting_tag = "TODO"
		rule_type = "TODO"
		original_name = "A"
		original_path = "test1.yar"
		source_id = 4
		id = 39
		predecessor_id = 37
		oldest_ancestor_id = 34
	condition:
		true or
		false or
		KK__33
}

rule B__35
{
	meta:
		__new_meta = "new"
		author = "https://github.com/xkucma00/yara-rules.git"
		tool = "TODO 0.1.0"
		description = "TODO"
		hunting_tag = "TODO"
		rule_type = "TODO"
		original_name = "B"
		original_path = "test2/tesst.yar"
		source_id = 4
		id = 35
		predecessor_id = false
		oldest_ancestor_id = false
	condition:
		true or
		false or
		pe.number_of_sections != 2 or
		false
}

rule KK__33__40
{
	meta:
		__author = "https://github.com/xkucma00/yara-rules.git"
		__tool = "TODO 0.1.0"
		__description = "TODO"
		__hunting_tag = "TODO"
		__rule_type = "TODO"
		__original_name = "KK"
		__original_path = "test1.yar"
		__source_id = 4
		__id = 33
		__predecessor_id = false
		__oldest_ancestor_id = false
		author = "https://github.com/xkucma00/yara-rules.git"
		tool = "TODO 0.1.0"
		description = "TODO"
		hunting_tag = "TODO"
		rule_type = "TODO"
		original_name = "KK__33"
		original_path = "hunting/third_party/yara-scraper.yar"
		source_id = 4
		id = 40
		predecessor_id = false
		oldest_ancestor_id = false
	condition:
		false
}

rule A__34__41
{
	meta:
		__author = "https://github.com/xkucma00/yara-rules.git"
		__tool = "TODO 0.1.0"
		__description = "TODO"
		__hunting_tag = "TODO"
		__rule_type = "TODO"
		__original_name = "A"
		__original_path = "test1.yar"
		__source_id = 4
		__id = 34
		__predecessor_id = false
		__oldest_ancestor_id = false
		author = "https://github.com/xkucma00/yara-rules.git"
		tool = "TODO 0.1.0"
		description = "TODO"
		hunting_tag = "TODO"
		rule_type = "TODO"
		original_name = "A__34"
		original_path = "hunting/third_party/yara-scraper.yar"
		source_id = 4
		id = 41
		predecessor_id = false
		oldest_ancestor_id = false
	condition:
		true or
		false or
		KK__33__40
}

rule B__35__42
{
	meta:
		____new_meta = "new"
		__author = "https://github.com/xkucma00/yara-rules.git"
		__tool = "TODO 0.1.0"
		__description = "TODO"
		__hunting_tag = "TODO"
		__rule_type = "TODO"
		__original_name = "B"
		__original_path = "test2/tesst.yar"
		__source_id = 4
		__id = 35
		__predecessor_id = false
		__oldest_ancestor_id = false
		author = "https://github.com/xkucma00/yara-rules.git"
		tool = "TODO 0.1.0"
		description = "TODO"
		hunting_tag = "TODO"
		rule_type = "TODO"
		original_name = "B__35"
		original_path = "hunting/third_party/yara-scraper.yar"
		source_id = 4
		id = 42
		predecessor_id = false
		oldest_ancestor_id = false
	condition:
		true or
		false or
		pe.number_of_sections != 2 or
		false
}

global rule ahoj__36__43 : test
{
	meta:
		____also_new = true
		____which = 2
		__author = "https://github.com/xkucma00/yara-rules.git"
		__tool = "TODO 0.1.0"
		__description = "TODO"
		__hunting_tag = "TODO"
		__rule_type = "TODO"
		__original_name = "ahoj"
		__original_path = "test2/tesst.yar"
		__source_id = 4
		__id = 36
		__predecessor_id = false
		__oldest_ancestor_id = false
		author = "https://github.com/xkucma00/yara-rules.git"
		tool = "TODO 0.1.0"
		description = "TODO"
		hunting_tag = "TODO"
		rule_type = "TODO"
		original_name = "ahoj__36"
		original_path = "hunting/third_party/yara-scraper.yar"
		source_id = 4
		id = 43
		predecessor_id = false
		oldest_ancestor_id = false
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

global rule ahoj__44 : test
{
	meta:
		__also_new = true
		__which = 2
		author = "https://github.com/xkucma00/yara-rules.git"
		tool = "TODO 0.1.0"
		description = "TODO"
		hunting_tag = "TODO"
		rule_type = "TODO"
		original_name = "ahoj"
		original_path = "test2/tesst.yar"
		source_id = 4
		id = 44
		predecessor_id = 38
		oldest_ancestor_id = 36
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

