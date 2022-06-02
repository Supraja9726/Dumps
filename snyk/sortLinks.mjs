import fs from "fs";
import path from 'path';
import { fileURLToPath } from 'url'
  
const linkFilters = [                    // Define array
    {test: /commit/i, category: "Commit"},
    {test: /vulnerable/i, category: "Vulnerable code"},
    {test: /issue/i, category: "Issue"},
    {test: /((.*\s)?PR(\s.*)?)|(pull request)/i, category: "Pull request"},
    {test: /advisory/i, category: "Advisory"},
    {test: /report|bug/i, category: "Bug report"},
    {test: /./, category: "Other"}
]

//console.log("linkFilters",linkFilters);


export function categorizeLinks(db) {   // categorizing links  - gets infoObjs

    console.log("db",db);
    const linksByType = db.reduce((acc, vuln) =>
        {
            const filter = linkFilters
                .find(({test}) => vuln.linksAndNames.some(({name}) => name.match(test)));
                
            const match = vuln.linksAndNames
                .find(({name}) => name.match(filter.test));
                
                console.log("vuln.linksAndNames",vuln.linksAndNames);

            acc[filter.category] = acc[filter.category] || [];

            const {linksAndNames, ...vulnInfo} = vuln;
            acc[filter.category].push({...match, ...vulnInfo});
            return acc;
        }, {}
    )

    const sorted = Object.entries(linksByType)
        .map(([key, links]) => [key, links.length])
        .sort((a,b) => b[1]-a[1]);

    console.log("Sorted:",sorted)
    return linksByType;
}

function isCLI() {
    const nodePath = path.resolve(process.argv[1]);  // returns absolute path - Accepts one parameter - should be a string value
    console.log("nodePath:",nodePath);  // Debug
    const modulePath = path.resolve(fileURLToPath(import.meta.url)); // exposes context specific url
    console.log("modulePath:",modulePath); // Debug
    return nodePath === modulePath;   // checks the datatype and compares two values and returns if true or false
}

if (isCLI()) {  // If nodePath === modulePath is true
    //console.log("Inside CLI If cond.");
    const db = JSON.parse(fs.readFileSync("linksDB2.json", "utf-8"))
    const linksByType = categorizeLinks(db);  // rerturned from the func
    //console.log("linksByType:",linksByType);
    fs.writeFileSync("./sortedLinks2.json", JSON.stringify(linksByType));
}
