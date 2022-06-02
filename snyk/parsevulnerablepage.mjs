import fetch from "node-fetch";
import DomParser from "dom-parser";
import fs from "fs";
import { fileURLToPath } from 'url'
//import { getLinks } from "./snykPages.mjs"


const parser = new DomParser();

const url = `https://snyk.io/vuln/npm%3Abigid-filter-recursive-parser`  // Should be passed dynamically
console.log("URL:",url);

const infoObjs = []

export async function parsepage() {         // URL should be passed dynamically here to this func
	const html = await fetch(url)
                .then(res => res.text());
        
        //console.log("html:",html);  // Debug
        console.log("**************************");
        
         for (var i = 0; i <=10; i++) {
         try {

                const htmlStr = await fetch(url)
                        .then(res => res.text())
                
              //  console.log("htmlStr",htmlStr);
                
                const html = parser.parseFromString(htmlStr);
                
              

                const linksAndNames = getLinks(html);
                console.log("linksAndNames",linksAndNames);
                
               // console.log("linksAndNames.length",linksAndNames.length);

                if (linksAndNames?.length) {

                    const info = getInfo(html);
                    infoObjs.push({linksAndNames, i, ...info})
                    console.log(infoObjs);
                }
            } catch (error) {
                throw error;
            }
            }
}

function getLinks(html) {
    const overview = html.getElementsByClassName("prose")[0];
    
    console.log("overview:",overview);

    // <li> with links and names
    const cardContent = overview
        ?.getElementsByClassName("card__content")[0];
    const sections = cardContent?.childNodes
        .filter(node => node.nodeName !== "#text");
    const referenceHeaderIndex = sections
        ?.findIndex(section => section.textContent.trim() === "References");
        
     console.log("referenceHeaderIndex:",referenceHeaderIndex);
 
    if (referenceHeaderIndex && referenceHeaderIndex !== -1) {
        const references = sections[referenceHeaderIndex + 1];
        
        const links = references.getElementsByTagName("a").map(element => element.getAttribute("href"));
        const names = references.getElementsByTagName("a").map(element => element.textContent);
           console.log("names:",names);
           console.log("links:",links);
        
        const linksAndNames = links.map((link, i) => {return {link, "name":names[i]}});
        
        return linksAndNames;
    }
}

parsepage();
