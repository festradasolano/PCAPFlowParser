/**
 * 
 */
package co.edu.unicauca.dtm.pcapflowparser.util;

import java.io.File;

/**
 * @author festradasolano
 *
 */
public final class Utils {
	
	/**
	 * @param file
	 * @param suffix
	 * @return
	 */
	public static String getFileName(File file, String suffix) {
		String name;
		// Get file name; remove extension if exists
		if (file.getName().lastIndexOf(".") > 0) {
			name = file.getName().substring(0, file.getName().lastIndexOf("."));
		} else {
			name = file.getName();
		}
		// Add suffix
		name += suffix;
		// Return file name
		return name;
	}
	
	/**
	 * @param file
	 * @param suffix
	 * @return
	 */
	public static String getFilePath(File file, String suffix) {
		// Get parent path
		String prefix = file.getParent() + File.separator;
		// Return file path
		return prefix + getFileName(file, suffix);
	}

}
