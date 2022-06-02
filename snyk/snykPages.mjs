import fetch from "node-fetch";
import DomParser from "dom-parser";
import fs from "fs";
import { categorizeLinks } from "./sortLinks.mjs";

const parser = new DomParser();


const url = num => `https://security.snyk.io/vuln/npm/${num}`

const regex = /href="(vuln\/(SNYK-JS-.*?-\d*|npm:.*?:\d*?))"/gm;

const infoObjs = []

async function main(){

    for (let i = 1; i <= 1; i++){  // 100, because at the moment of accessing Snyk database there were 100 pages with npm vulnerabilities
        console.log("page: " + i);  // Prints the page number
        const html = await fetch(url(i))
                .then(res => res.text());
         console.log("url:",url(i)); 
        const vulnPages = Array.from(html.matchAll(regex)).map(match => "https://security.snyk.io/" + match[1]);
       console.log("VulnPages: ", vulnPages.length);
        
        for(const page of vulnPages){
            try {

                const htmlStr = await fetch(page)
                        .then(res => res.text())
                
                const html = parser.parseFromString(htmlStr);

                const linksAndNames = getLinks(html);

                if (linksAndNames?.length) {  
                    const info = getInfo(html);
                    console.log("info",info); // Debug
                    infoObjs.push({linksAndNames, page, ...info})
                }
            } catch (error) {
                console.log(page);
                throw error;
            }
        }
    }
    console.log("Info objects done");
    console.log("Objects: ", infoObjs.length);
    console.log("Unique: ", new Set(infoObjs.map(obj => obj.packageName)));
    const categorized = categorizeLinks(infoObjs);
    console.log("Writing file");
    const fileName = process.argv[2];
    console.log(fileName);
    fs.writeFileSync(fileName, JSON.stringify(categorized, null, 2)); //file with sorted links and details about every vulnerability
    console.log("write file done");
 }

function getLinks(html){

  //  console.log(html);
	const overview = html.getElementsByClassName("vue--markdown-to-html markdown-description")[0].textContent;
  	console.log("overview",overview);

    const packageName = html.getElementsByTagName("title")[0].innerHTML.split(" ")[4]
    console.log("title:",packageName);

   
   
    
 
    }


function getInfo(html){

    const header = html.getElementsByClassName("header__lede")[0];
    console.log("header",header);
    
    const packageName = header.getElementsByClassName("breadcrumbs__list-item__link")[0].textContent;
    console.log("packageName",packageName);
    
    
    const versions = header.lastChild.textContent;
    console.log("versions",versions);

    const box = html.getElementsByClassName("vuln-sidebar-offset")[0];
    console.log("box",box);
    
    const smallerBox = box.childNodes.filter(n => !n.text).slice(-1)[0];
    console.log("smallerBox",smallerBox);

    const info = smallerBox.getElementsByTagName("a").map(el => el.textContent).filter(el => el.trim());
    console.log("info",info);

    const vulnType = html.getElementsByClassName("vue--heading title")[0].textContent.split("\n")[1].trim();
    console.log("vulnType",vulnType);
    
    const details = html.getElementsByClassName("card__content")[1]
                    .getElementsByTagName("p")
                    .slice(0,2)
                    .reduce((acc, p) => acc + p.textContent, "  ")
     console.log("details",details);

    return {vulnType,
            details,
            "CVE": info.find(value => value.includes("CVE")),
            "CWE": info.find(value => value.includes("CWE")),
            packageName,
            versions
            }
    
}


 main();

