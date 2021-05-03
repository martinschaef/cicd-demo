/**
* OWASP Benchmark Project
*
* This file is part of the Open Web Application Security Project (OWASP)
* Benchmark Project For details, please see
* <a href="https://www.owasp.org/index.php/Benchmark">https://www.owasp.org/index.php/Benchmark</a>.
*
* The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
* of the GNU General Public License as published by the Free Software Foundation, version 2.
*
* The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
* even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details
*
* @author Martin Schaef
* @created 2021
*/

package org.owasp.benchmark.score.parsers;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.json.JSONArray;
import org.json.JSONObject;
import org.owasp.benchmark.score.BenchmarkScore;

public class AWSCodeGuruReader extends Reader {

	public TestResults parse( File f ) throws Exception {
		String content = new String(Files.readAllBytes(Paths.get(f.getPath())));

		JSONObject obj = new JSONObject(content);
		int version = 1; // TODO Need a version string

		final TestResults testResults =
            new TestResults( "AWS CodeGuru Reviewer" ,true,TestResults.ToolType.SAST);

		testResults.setTime("TODO"); // NEED THE SCAN TIME

        final int hackCWENumber = Integer.parseInt(f.getName().replace(".json", "")); // HACK


        JSONArray recommendations = obj.getJSONArray("RecommendationSummaries");
		for (int i = 0; i < recommendations.length(); i++)
		{
			TestCaseResult testCaseResult = parseCodeGuruFinding( recommendations.getJSONObject(i), hackCWENumber );
			if ( testCaseResult != null ) {
                testResults.put( testCaseResult );
			}
		}
		
		return testResults;
	}


	private TestCaseResult parseCodeGuruFinding(JSONObject finding, int cweNumber) {
	    try {
            TestCaseResult testCaseResult = new TestCaseResult();
            final String filePath = finding.getString("FilePath");
            if (filePath.contains(BenchmarkScore.BENCHMARKTESTNAME)) {
                final String fileName = new File(filePath).getName();
                final String benchmarkNumber = fileName.replace(BenchmarkScore.BENCHMARKTESTNAME, "")
                                                       .replace(".java", "");
                testCaseResult.setNumber(Integer.parseInt(benchmarkNumber));
                testCaseResult.setCWE(cweNumber); // TODO: HACK
                testCaseResult.setCategory("TODO"); // TODO
                testCaseResult.setEvidence(finding.getString("Description"));
                return testCaseResult;
            }
        }  catch (Exception e ) {
            e.printStackTrace();
        }
	    return null;
    }


}
